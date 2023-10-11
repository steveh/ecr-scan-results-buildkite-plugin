package registry

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

var registryImageExpr = regexp.MustCompile(`^(?P<registryId>[^.]+)\.dkr\.ecr\.(?P<region>[^.]+).amazonaws.com/(?P<repoName>[^:]+)(?::(?P<tag>.+))?$`)

type ScanFindings struct {
	types.ImageScanFindings
}

type RegistryInfo struct {
	// RegistryID is the AWS ECR account ID of the source registry.
	RegistryID string
	// Region is the AWS region of the registry.
	Region string
	// Name is the ECR repository name.
	Name string
	// Tag is the image label or an image digest.
	Tag string
}

type ECRAPI interface {
	DescribeImageScanFindings(context.Context, *ecr.DescribeImageScanFindingsInput, ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
	DescribeImages(context.Context, *ecr.DescribeImagesInput, ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
}

func (i RegistryInfo) String() string {
	return fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s:%s", i.RegistryID, i.Region, i.Name, i.Tag)
}

func RegistryInfoFromURL(url string) (RegistryInfo, error) {
	info := RegistryInfo{}
	names := registryImageExpr.SubexpNames()
	match := registryImageExpr.FindStringSubmatch(url)
	if match == nil {
		return info, fmt.Errorf("invalid registry URL: %s", url)
	}

	// build the struct using the named subexpressions from the expression
	for i, value := range match {
		nm := names[i]
		switch nm {
		case "registryId":
			info.RegistryID = value
		case "region":
			info.Region = value
		case "repoName":
			info.Name = value
		case "tag":
			info.Tag = value
		}
	}

	return info, nil
}

type RegistryScan struct {
	Client          ECRAPI
	MinAttemptDelay time.Duration
	MaxAttemptDelay time.Duration
	MaxTotalDelay   time.Duration
}

func NewRegistryScan(config aws.Config) (*RegistryScan, error) {
	client := ecr.NewFromConfig(config)

	// wait between attempts for between 3 and 15 secs (exponential backoff)
	// wait for a maximum of 3 minutes
	minAttemptDelay := 3 * time.Second
	maxAttemptDelay := 15 * time.Second
	maxTotalDelay := 3 * time.Minute

	return &RegistryScan{
		Client:          client,
		MinAttemptDelay: minAttemptDelay,
		MaxAttemptDelay: maxAttemptDelay,
		MaxTotalDelay:   maxTotalDelay,
	}, nil
}

func (r *RegistryScan) GetLabelDigest(ctx context.Context, imageInfo RegistryInfo) (RegistryInfo, error) {
	out, err := r.Client.DescribeImages(ctx, &ecr.DescribeImagesInput{
		RegistryId:     &imageInfo.RegistryID,
		RepositoryName: &imageInfo.Name,
		ImageIds: []types.ImageIdentifier{
			{
				ImageTag: &imageInfo.Tag,
			},
		},
	})
	if err != nil {
		return RegistryInfo{}, err
	}
	if len(out.ImageDetails) == 0 {
		return RegistryInfo{}, fmt.Errorf("no image found for image %s", imageInfo)
	}

	// copy input and update tag from label to digest
	digestInfo := imageInfo
	digestInfo.Tag = *out.ImageDetails[0].ImageDigest

	return digestInfo, nil
}

func (r *RegistryScan) WaitForScanFindings(ctx context.Context, digestInfo RegistryInfo) error {
	waiter := ecr.NewImageScanCompleteWaiter(r.Client)

	return waiter.Wait(ctx, &ecr.DescribeImageScanFindingsInput{
		RegistryId:     &digestInfo.RegistryID,
		RepositoryName: &digestInfo.Name,
		ImageId: &types.ImageIdentifier{
			ImageDigest: &digestInfo.Tag,
		},
	}, r.MaxAttemptDelay, func(opts *ecr.ImageScanCompleteWaiterOptions) {
		/*
			We must copy this function outside the closure to avoid an infinite loop
			If we copy it inside the closure the compiler will assign it to a pointer
			to itself
		*/
		defaultRetryableFunc := opts.Retryable
		customRetryable := func(ctx context.Context, params *ecr.DescribeImageScanFindingsInput,
			output *ecr.DescribeImageScanFindingsOutput, err error) (bool, error) {
			if err != nil {
				fmt.Printf("error waiting for scan findings %v\n", err)
			}
			return defaultRetryableFunc(ctx, params, output, err)
		}
		opts.LogWaitAttempts = true
		opts.MinDelay = r.MinAttemptDelay
		opts.MaxDelay = r.MaxAttemptDelay
		opts.Retryable = customRetryable
	})
}

func (r *RegistryScan) GetScanFindings(ctx context.Context, digestInfo RegistryInfo) (*ScanFindings, error) {
	pg := ecr.NewDescribeImageScanFindingsPaginator(r.Client, &ecr.DescribeImageScanFindingsInput{
		RegistryId:     &digestInfo.RegistryID,
		RepositoryName: &digestInfo.Name,
		ImageId: &types.ImageIdentifier{
			ImageDigest: &digestInfo.Tag,
		},
	})

	findings := []types.ImageScanFinding{}
	enhancedFindings := []types.EnhancedImageScanFinding{}

	imageScanFindings := types.ImageScanFindings{}

	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		// no more pages
		if page == nil {
			break
		}

		if !pg.HasMorePages() {
			imageScanFindings = *page.ImageScanFindings
		}

		findings = append(findings, page.ImageScanFindings.Findings...)
		enhancedFindings = append(enhancedFindings, page.ImageScanFindings.EnhancedFindings...)
	}

	imageScanFindings.Findings = findings
	imageScanFindings.EnhancedFindings = enhancedFindings

	return &ScanFindings{
		ImageScanFindings: imageScanFindings,
	}, nil
}

// Filters

type FindingFilter = func(types.ImageScanFinding) bool

func FilterFindings(allFindings ScanFindings, filters ...FindingFilter) ScanFindings {
	filteredFindings := ScanFindings{
		ImageScanFindings: types.ImageScanFindings{
			FindingSeverityCounts:        make(map[string]int32),
			Findings:                     []types.ImageScanFinding{},
			EnhancedFindings:             allFindings.EnhancedFindings, // we are not using enhanced findings just yet
			ImageScanCompletedAt:         allFindings.ImageScanCompletedAt,
			VulnerabilitySourceUpdatedAt: allFindings.VulnerabilitySourceUpdatedAt,
		},
	}
	for _, finding := range allFindings.Findings {
		keep := true

		for _, filter := range filters {
			if !filter(finding) {
				keep = false
				break
			}
		}

		if keep {
			filteredFindings.Findings = append(filteredFindings.Findings, finding)
			filteredFindings.FindingSeverityCounts[string(finding.Severity)]++
		}
	}

	return filteredFindings
}

func FilterIgnoredNames(namesToIgnore []string) FindingFilter {
	return func(finding types.ImageScanFinding) bool {
		return !slices.Contains(namesToIgnore, *finding.Name)
	}
}

func FilterMinSeverity(minSeverity types.FindingSeverity) FindingFilter {
	return func(finding types.ImageScanFinding) bool {
		return severityLevel(finding.Severity) >= severityLevel(minSeverity)
	}
}

func severityLevel(severity types.FindingSeverity) int {
	switch severity {
	case types.FindingSeverityUndefined:
		return 0
	case types.FindingSeverityInformational:
		return 1
	case types.FindingSeverityLow:
		return 2
	case types.FindingSeverityMedium:
		return 3
	case types.FindingSeverityHigh:
		return 4
	case types.FindingSeverityCritical:
		return 5
	default: // unknown severity
		return -1
	}
}
