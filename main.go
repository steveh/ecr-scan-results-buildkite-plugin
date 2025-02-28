package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v3"

	"github.com/buildkite/ecrscanresults/src/buildkite"
	"github.com/buildkite/ecrscanresults/src/env"
	"github.com/buildkite/ecrscanresults/src/registry"
	"github.com/buildkite/ecrscanresults/src/report"
	"github.com/buildkite/ecrscanresults/src/runtimeerrors"
)

const pluginEnvironmentPrefix = "BUILDKITE_PLUGIN_ECR_SCAN_RESULTS"

type Config struct {
	Repository                 string   `envconfig:"IMAGE_NAME"    required:"true"    split_words:"true"`
	ImageLabel                 string   `envconfig:"IMAGE_LABEL"   split_words:"true"`
	CriticalSeverityThreshold  int32    `envconfig:"MAX_CRITICALS" split_words:"true"`
	HighSeverityThreshold      int32    `envconfig:"MAX_HIGHS"     split_words:"true"`
	IgnoredVulnerabilities     []string `envconfig:"IGNORE"`
	IgnoredVulnerabilitiesFile string   `envconfig:"IGNORE_FILE" default:".buildkite/ignored_cves.yml"`
	MinSeverity                Severity `envconfig:"MIN_SEVERITY" default:"high" split_words:"true"`
	Help                       string   `envconfig:"HELP" default:""`
}

type Severity types.FindingSeverity

type IgnoreList struct {
	Vulnerabilities []string `yaml:"Vulnerabilities"`
}

func (s *Severity) Decode(value string) error {
	sev := types.FindingSeverity(strings.ToUpper(strings.TrimSpace(value)))
	if allowedSevs := new(types.FindingSeverity).Values(); !slices.Contains(allowedSevs, sev) {
		return fmt.Errorf("severity must be one of: %v", allowedSevs)
	}
	*s = Severity(sev)
	return nil
}

func main() {
	pluginConfig, err := parseConfig()
	if err != nil {
		buildkite.LogFailuref(err.Error())
		os.Exit(1)
	}
	ctx := context.Background()
	agent := buildkite.Agent{}

	err = runCommand(ctx, *pluginConfig, agent)
	if err != nil {
		buildkite.LogFailuref("plugin execution failed: %s\n", err.Error())

		// For this plugin, we don't want to block the build on most errors:
		// scan access and availability can be quite flakey. For this reason, we
		// wrap most issues in a non-fatal error type.
		if runtimeerrors.IsFatal(err) {
			os.Exit(1)
		} else {
			// Attempt to annotate the build with the issue, but it's OK if the
			// annotation fails. We annotate to notify the user of the issue,
			// otherwise it would be lost in the log.
			annotation := fmt.Sprintf("ECR scan results plugin could not create a result for the image %s", "")
			_ = agent.Annotate(ctx, annotation, "error", hash(pluginConfig.Repository))
		}
	}
}

func parseConfig() (*Config, error) {
	var pluginConfig Config
	if err := envconfig.Process(pluginEnvironmentPrefix, &pluginConfig); err != nil {

		return nil, fmt.Errorf("plugin configuration error: %w", err)
	}
	if pluginConfig.CriticalSeverityThreshold < 0 {
		return nil, errors.New("max-criticals must be greater than or equal to 0")
	}
	if pluginConfig.HighSeverityThreshold < 0 {
		return nil, errors.New("max-highs must be greater than or equal to 0")
	}

	if len(pluginConfig.IgnoredVulnerabilities) == 0 {
		prefix := fmt.Sprintf("%s_%s_", pluginEnvironmentPrefix, "IGNORE")
		pluginConfig.IgnoredVulnerabilities = env.ParseWithPrefix(prefix)
	}

	ignoreFile, err := os.ReadFile(pluginConfig.IgnoredVulnerabilitiesFile)
	if err != nil {
		buildkite.Logf("Unable to read ignore file %s", err)
	}
	var ignoreList IgnoreList
	err = yaml.Unmarshal(ignoreFile, &ignoreList)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse Ignore file: %w", err)
	}

	for _, v := range ignoreList.Vulnerabilities {
		pluginConfig.IgnoredVulnerabilities = append(pluginConfig.IgnoredVulnerabilities, v)
	}
	pluginConfig.IgnoredVulnerabilities = slices.Compact(pluginConfig.IgnoredVulnerabilities)
	return &pluginConfig, nil
}

func runCommand(ctx context.Context, pluginConfig Config, agent buildkite.Agent) error {
	buildkite.Logf("Scan results report requested for %s\n", pluginConfig.Repository)
	buildkite.Logf("Thresholds: criticals %d highs %d\n", pluginConfig.CriticalSeverityThreshold, pluginConfig.HighSeverityThreshold)

	imageID, err := registry.RegistryInfoFromURL(pluginConfig.Repository)
	if err != nil {
		return err
	}

	awsConfig, err := config.LoadDefaultConfig(ctx, config.WithRegion(imageID.Region))
	if err != nil {
		return runtimeerrors.NonFatal("could not configure AWS access", err)
	}

	scan, err := registry.NewRegistryScan(awsConfig)
	if err != nil {
		return runtimeerrors.NonFatal("could not set up ECR access", err)
	}

	buildkite.Logf("Getting image digest for %s\n", imageID)
	imageDigest, err := scan.GetLabelDigest(ctx, imageID)
	if err != nil {
		return runtimeerrors.NonFatal("could not find digest for image", err)
	}

	buildkite.Logf("Digest: %s\n", imageDigest)

	buildkite.LogGroupf(":ecr: Creating ECR scan results report for %s\n", imageID)
	err = scan.WaitForScanFindings(ctx, imageDigest)
	if err != nil {
		return fmt.Errorf("could not retrieve scan results %w", err)
	}

	buildkite.Log("report ready, retrieving ...")

	allFindings, err := scan.GetScanFindings(ctx, imageDigest)
	if err != nil {
		return runtimeerrors.NonFatal("could not retrieve scan results", err)
	}

	buildkite.Logf("total findings (unfiltered): %d\n", len(allFindings.ImageScanFindings.Findings))

	filteredFindings := registry.FilterFindings(*allFindings,
		registry.FilterIgnoredNames(pluginConfig.IgnoredVulnerabilities),
		registry.FilterMinSeverity(types.FindingSeverity(pluginConfig.MinSeverity)),
	)

	buildkite.Logf("total findings (filtered): %d\n", len(filteredFindings.ImageScanFindings.Findings))
	buildkite.Logf("ignored vulnerabilities (%d): %v\n",
		len(pluginConfig.IgnoredVulnerabilities),
		pluginConfig.IgnoredVulnerabilities,
	)

	criticalFindingsCount := filteredFindings.ImageScanFindings.FindingSeverityCounts["CRITICAL"]
	highFindingsCount := filteredFindings.ImageScanFindings.FindingSeverityCounts["HIGH"]
	isOverThreshold :=
		criticalFindingsCount > pluginConfig.CriticalSeverityThreshold ||
			highFindingsCount > pluginConfig.HighSeverityThreshold

	buildkite.Logf("Severity counts: critical=%d high=%d overThreshold=%v\n",
		criticalFindingsCount,
		highFindingsCount,
		isOverThreshold,
	)

	buildkite.Log("Creating report annotation...")
	annotationCtx := report.AnnotationContext{
		Image:                     imageID,
		ImageLabel:                pluginConfig.ImageLabel,
		ScanFindings:              filteredFindings.ImageScanFindings,
		CriticalSeverityThreshold: pluginConfig.CriticalSeverityThreshold,
		HighSeverityThreshold:     pluginConfig.HighSeverityThreshold,
		Help:                      pluginConfig.Help,
	}

	annotation, err := annotationCtx.Render()
	if err != nil {
		return runtimeerrors.NonFatal("could not render report", err)
	}
	buildkite.Log("done.")

	annotationStyle := "info"
	if isOverThreshold {
		annotationStyle = "error"
	} else if criticalFindingsCount > 0 || highFindingsCount > 0 {
		annotationStyle = "warning"
	}

	err = agent.Annotate(ctx, string(annotation), annotationStyle, "scan_results_"+imageDigest.Tag)
	if err != nil {
		return runtimeerrors.NonFatal("could not annotate build", err)
	}

	buildkite.Log("Uploading report as an artifact...")
	filename := fmt.Sprintf("result.%s.html", strings.TrimPrefix(imageDigest.Tag, "sha256:"))
	err = os.WriteFile(filename, annotation, fs.ModePerm)
	if err != nil {
		return runtimeerrors.NonFatal("could not write report artifact", err)
	}

	err = agent.ArtifactUpload(ctx, "result*.html")
	if err != nil {
		return runtimeerrors.NonFatal("could not upload report artifact", err)
	}

	buildkite.Log("done.")

	// exceeding threshold is a fatal error
	if isOverThreshold {
		return errors.New("vulnerability threshold exceeded")
	}

	return nil
}

func hash(data ...string) string {
	h := sha256.New()
	for _, d := range data {
		h.Write([]byte(d))
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}
