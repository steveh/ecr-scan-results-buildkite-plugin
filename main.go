package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/buildkite/ecrscanresults/src/buildkite"
	"github.com/buildkite/ecrscanresults/src/env"
	"github.com/buildkite/ecrscanresults/src/finding"
	"github.com/buildkite/ecrscanresults/src/findingconfig"
	"github.com/buildkite/ecrscanresults/src/registry"
	"github.com/buildkite/ecrscanresults/src/report"
	"github.com/buildkite/ecrscanresults/src/runtimeerrors"
	"github.com/kelseyhightower/envconfig"
	"github.com/sourcegraph/conc/iter"
	"gopkg.in/yaml.v3"
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
			annotation := "ECR scan results plugin could not create a result for the image"
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
		return nil, fmt.Errorf("failed to parse Ignore file: %w", err)
	}

	pluginConfig.IgnoredVulnerabilities = slices.Compact(append(pluginConfig.IgnoredVulnerabilities, ignoreList.Vulnerabilities...))
	return &pluginConfig, nil
}

func runCommand(ctx context.Context, pluginConfig Config, agent buildkite.Agent) error {
	buildkite.Logf("Scan results report requested for %s\n", pluginConfig.Repository)
	buildkite.Logf("Thresholds: criticals %d highs %d\n", pluginConfig.CriticalSeverityThreshold, pluginConfig.HighSeverityThreshold)

	buildkite.Logf("Loading finding ignore files ...\n")

	ignoreConfig, err := findingconfig.LoadFromDefaultLocations(findingconfig.DefaultSystemClock())
	if err != nil {
		return runtimeerrors.NonFatal("could not load finding ignore configuration", err)
	}

	if len(ignoreConfig) == 0 {
		buildkite.Logf("No ignore rules loaded, or all rules have expired.\n")
	} else {
		buildkite.Logf("Loaded %d ignore rules:\n", len(ignoreConfig))
		for _, ignore := range ignoreConfig {
			buildkite.Logf("  - %s\n", ignore)
		}
	}

	imageID, err := registry.ParseReferenceFromURL(pluginConfig.Repository)
	if err != nil {
		return err
	}

	buildkite.LogGroupf(":ecr: Creating ECR scan results report for %s\n", imageID)

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

	buildkite.Logf("Resolve images (and platforms) for %s\n", imageID)
	repo := registry.NewRemoteRepository()
	imageDigests, err := repo.ResolveImageReferences(imageDigest)
	if err != nil {
		return runtimeerrors.NonFatal("could not find digest for image", err)
	}

	buildkite.Logf("Found %d images for digest: %s\n", len(imageDigests), imageDigest)

	if len(imageDigests) == 0 {
		return runtimeerrors.NonFatal(
			fmt.Sprintf("image index %s did not reference any other images: no scan results to retrieve", imageDigest),
			nil,
		)
	}

	// now download all the results and create a merged report
	buildkite.Logf("Attempting to retrieve scan results for %d image(s)", len(imageDigests))
	summaries, err := iter.MapErr(imageDigests, func(image *registry.PlatformImageReference) (finding.Summary, error) {
		return getImageScanSummary(ctx, scan, *image, ignoreConfig)
	})
	if err != nil {
		return fmt.Errorf("could not retrieve scan results %w", err)
	}

	// merge the set of returned summaries into a single one ready for reporting.
	findingSummary := finding.MergeSummaries(summaries)

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

	status := findingSummary.Status(pluginConfig.CriticalSeverityThreshold, pluginConfig.HighSeverityThreshold)
	if status == finding.StatusAllPlatformsFailed {
		// Failing on all platforms is terminating but not fatal to the build:
		// builds are only blocked if thresholds are exceeded. When only some
		// platforms have failed, the report will include details of the partial
		// failure.
		return runtimeerrors.NonFatal("no scan results could be retrieved", nil)
	}

	buildkite.Log("Creating report annotation...")
	annotationCtx := report.AnnotationContext{
		Image:                     imageID,
		ImageLabel:                pluginConfig.ImageLabel,
		FindingSummary:            findingSummary,
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

	err = agent.Annotate(ctx, string(annotation), annotationStyle, "scan_results_"+imageDigest.Digest)
	if err != nil {
		return runtimeerrors.NonFatal("could not annotate build", err)
	}

	buildkite.Log("Uploading report as an artifact...")
	filename := fmt.Sprintf("result.%s.html", strings.TrimPrefix(imageDigest.Digest, "sha256:"))
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

// getImageScanSummary retrieves the scan results for the given image digest and
// returns the initial summary for the image. This function may be called in
// parallel for multiple images.
func getImageScanSummary(ctx context.Context, scan *registry.RegistryScan, imageDigest registry.PlatformImageReference, ignoreConfig []findingconfig.Ignore) (finding.Summary, error) {
	err := scan.WaitForScanFindings(ctx, imageDigest.ImageReference)
	if err != nil {
		return finding.Summary{}, err
	}

	buildkite.Log("report ready, retrieving ...")

	findings, err := scan.GetScanFindings(ctx, imageDigest.ImageReference)
	if err != nil {
		return finding.Summary{}, err
	}

	numFindings := len(findings.ImageScanFindings.Findings)

	buildkite.Logf("retrieved. %d findings in report.\n", numFindings)

	findingSummary := finding.Summarize(findings, imageDigest.Platform, ignoreConfig)

	return findingSummary, nil
}

// hash returns a hex-encoded sha256 hash of the given strings.
func hash(data ...string) string {
	h := sha256.New()
	for _, d := range data {
		h.Write([]byte(d))
	}
	return hex.EncodeToString(h.Sum(nil))
}
