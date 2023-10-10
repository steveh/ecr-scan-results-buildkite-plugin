package registry

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryInfoFromURLSucceeds(t *testing.T) {
	cases := []struct {
		test     string
		url      string
		expected RegistryInfo
	}{
		{
			test: "Url with label",
			url:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo:latest",
			expected: RegistryInfo{
				RegistryID: "123456789012",
				Region:     "us-west-2",
				Name:       "test-repo",
				Tag:        "latest",
			},
		},
		{
			test: "Url without label",
			url:  "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo",
			expected: RegistryInfo{
				RegistryID: "123456789012",
				Region:     "us-west-2",
				Name:       "test-repo",
				Tag:        "",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.test, func(t *testing.T) {
			info, err := RegistryInfoFromURL(c.url)
			require.NoError(t, err)
			assert.Equal(t, c.expected, info)
		})
	}
}

func TestRegistryInfoFromURLFails(t *testing.T) {
	url := "123456789012.dkr.ecr.us-west-2.amazonaws.com"

	info, err := RegistryInfoFromURL(url)
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid registry URL")

	assert.Equal(t, RegistryInfo{}, info)
}

func TestFilterFindings(t *testing.T) {
	sampleFindings := ScanFindings{
		ImageScanFindings: types.ImageScanFindings{
			Findings: []types.ImageScanFinding{
				{
					Name:     aws.String("cve-1"),
					Severity: types.FindingSeverityLow,
				},
				{
					Name:     aws.String("cve-2"),
					Severity: types.FindingSeverityMedium,
				},
				{
					Name:     aws.String("cve-3"),
					Severity: types.FindingSeverityHigh,
				},
				{
					Name:     aws.String("cve-4"),
					Severity: types.FindingSeverityHigh,
				},
			},
		},
	}

	type args struct {
		allFindings ScanFindings
		filters     []FindingFilter
	}
	tests := []struct {
		name   string
		args   args
		wantFn func(ScanFindings) bool
	}{
		{
			name: "keep all",
			args: args{
				allFindings: sampleFindings,
				filters: []FindingFilter{
					func(types.ImageScanFinding) bool { return true },
				},
			},
			wantFn: func(sf ScanFindings) bool {
				return len(sf.Findings) == len(sampleFindings.Findings)
			},
		},
		{
			name: "skip all",
			args: args{
				allFindings: sampleFindings,
				filters: []FindingFilter{
					func(types.ImageScanFinding) bool { return false },
				},
			},
			wantFn: func(sf ScanFindings) bool {
				return len(sf.Findings) == 0
			},
		},
		{
			name: "ignore cev-2",
			args: args{
				allFindings: sampleFindings,
				filters: []FindingFilter{
					FilterIgnoredNames([]string{"cve-2"}),
				},
			},
			wantFn: func(sf ScanFindings) bool {
				return len(sf.Findings) == 3
			},
		},
		{
			name: "sev high+",
			args: args{
				allFindings: sampleFindings,
				filters: []FindingFilter{
					FilterMinSeverity(types.FindingSeverityHigh),
				},
			},
			wantFn: func(sf ScanFindings) bool {
				return len(sf.Findings) == 2 && sf.FindingSeverityCounts["HIGH"] == 2
			},
		},
		{
			name: "multiple filters",
			args: args{
				allFindings: sampleFindings,
				filters: []FindingFilter{
					FilterMinSeverity(types.FindingSeverityHigh),
					func(types.ImageScanFinding) bool { return false },
				},
			},
			wantFn: func(sf ScanFindings) bool {
				return len(sf.Findings) == 0
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterFindings(tt.args.allFindings, tt.args.filters...)
			assert.True(t, tt.wantFn(got))
		})
	}
}

type mockedDescribeImageScanFindings struct {
	ECRAPI
}

func (m mockedDescribeImageScanFindings) DescribeImageScanFindings(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, opts ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error) {
	return nil, &types.ReferencedImagesNotFoundException{}
}

func TestWaitForScanFindings(t *testing.T) {
	r := &RegistryScan{
		Client:          &mockedDescribeImageScanFindings{},
		MinAttemptDelay: 1 * time.Millisecond,
		MaxAttemptDelay: 2 * time.Millisecond,
		MaxTotalDelay:   100 * time.Millisecond,
	}
	err := r.WaitForScanFindings(context.TODO(), RegistryInfo{})
	assert.Error(t, err)
}
