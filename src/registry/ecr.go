package registry

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

var registryImageExpr = regexp.MustCompile(`^(?P<registryId>[^.]+)\.dkr\.ecr\.(?P<region>[^.]+).amazonaws.com/(?P<repoName>[^:@]+)(?::(?P<tag>.+))?(?:@(?P<digest>.+))?$`)

type ScanFindings struct {
	types.ImageScanFindings
	ImageScanStatus types.ImageScanStatus
}

type ImageReference struct {
	// RegistryID is the AWS ECR account ID of the source registry.
	RegistryID string
	// Region is the AWS region of the registry.
	Region string
	// Name is the ECR repository name.
	Name string
	// Digest is the image digest segment of the image reference, often prefixed with sha256:.
	Digest string
	// Tag is the image label segment of the image reference
	Tag string
}

type ECRAPI interface {
	DescribeImageScanFindings(ctx context.Context, input *ecr.DescribeImageScanFindingsInput, fn ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
	DescribeImages(ctx context.Context, input *ecr.DescribeImagesInput, fn ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
}

// ID returns the known identifier for the image: this is the digest if present, otherwise the tag.
func (i ImageReference) ID() string {
	if i.Digest != "" {
		return i.Digest
	}
	return i.Tag
}

func (i ImageReference) DisplayName() string {
	return fmt.Sprintf("%s%s%s", i.Name, i.tagRef(), i.digestRef())
}

func (i ImageReference) String() string {
	return fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s%s%s", i.RegistryID, i.Region, i.Name, i.tagRef(), i.digestRef())
}

func (i ImageReference) tagRef() string {
	if i.Tag == "" {
		return ""
	}

	return ":" + i.Tag
}

func (i ImageReference) digestRef() string {
	if i.Digest == "" {
		return ""
	}

	return "@" + i.Digest
}

// WithDigest returns a copy of the image reference with the digest set to the
// given value. The tag, if any, is cleared.
func (i ImageReference) WithDigest(digest string) ImageReference {
	ref := i
	ref.Digest = digest
	ref.Tag = ""

	return ref
}

// ParseReferenceFromURL parses an image reference from a supplied ECR image
// identifier.
func ParseReferenceFromURL(url string) (ImageReference, error) {
	info := ImageReference{}
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
		case "digest":
			info.Digest = value
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

func (r *RegistryScan) GetLabelDigest(ctx context.Context, imageInfo ImageReference) (ImageReference, error) {
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
		return ImageReference{}, err
	}
	if len(out.ImageDetails) == 0 {
		return ImageReference{}, fmt.Errorf("no image found for image %s", imageInfo)
	}

	imageDetail := out.ImageDetails[0]

	// copy input and update tag from label to digest
	digestInfo := imageInfo.WithDigest(aws.ToString(imageDetail.ImageDigest))

	return digestInfo, nil
}

func (r *RegistryScan) WaitForScanFindings(ctx context.Context, digestInfo ImageReference) error {
	waiter := ecr.NewImageScanCompleteWaiter(r.Client)

	err := waiter.Wait(ctx, &ecr.DescribeImageScanFindingsInput{
		RegistryId:     &digestInfo.RegistryID,
		RepositoryName: &digestInfo.Name,
		ImageId: &types.ImageIdentifier{
			ImageDigest: &digestInfo.Digest,
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

	// It is not good style to compare the error string, but this is the only way
	// to capture that the scan failed, but everything else is hunky dory. We
	// return nil here so that the caller will gather the scan results, and
	// communicate to the user the reason this image has no results. "FAILURE" is
	// returned when the image is unsupported, for example, and we want to
	// communicate this properly to the user.
	if err != nil && err.Error() == "waiter state transitioned to Failure" {
		return nil
	}

	return err
}

func (r *RegistryScan) GetScanFindings(ctx context.Context, digestInfo ImageReference) (*ScanFindings, error) {
	pg := ecr.NewDescribeImageScanFindingsPaginator(r.Client, &ecr.DescribeImageScanFindingsInput{
		RegistryId:     &digestInfo.RegistryID,
		RepositoryName: &digestInfo.Name,
		ImageId: &types.ImageIdentifier{
			ImageDigest: &digestInfo.Digest,
		},
	})

	var findings []types.ImageScanFinding
	var enhancedFindings []types.EnhancedImageScanFinding
	var latestPageFindings types.ImageScanFindings
	var latestPageStatus types.ImageScanStatus

	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		// no more pages
		if page == nil {
			break
		}

		if page.ImageScanFindings != nil {
			latestPageFindings = *page.ImageScanFindings

			findings = append(findings, latestPageFindings.Findings...)
			enhancedFindings = append(enhancedFindings, latestPageFindings.EnhancedFindings...)
		}

		if page.ImageScanStatus != nil {
			latestPageStatus = *page.ImageScanStatus
		}
	}

	latestPageFindings.Findings = findings
	latestPageFindings.EnhancedFindings = enhancedFindings

	return &ScanFindings{
		ImageScanFindings: latestPageFindings,
		ImageScanStatus:   latestPageStatus,
	}, nil
}
