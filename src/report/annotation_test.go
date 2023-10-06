package report_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/MarvinJWendt/testza"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/buildkite/ecrscanresults/src/registry"
	"github.com/buildkite/ecrscanresults/src/report"
)

func TestReports(t *testing.T) {
	cases := []struct {
		name string
		data report.AnnotationContext
	}{
		{
			name: "no vulnerabilities",
			data: report.AnnotationContext{
				Image: registry.RegistryInfo{
					RegistryID: "0123456789",
					Region:     "us-west-2",
					Name:       "test-repo",
					Tag:        "digest-value",
				},
				ImageLabel:                "",
				ScanFindings:              types.ImageScanFindings{},
				CriticalSeverityThreshold: 0,
				HighSeverityThreshold:     0,
			},
		},
		{
			name: "image label",
			data: report.AnnotationContext{
				Image: registry.RegistryInfo{
					RegistryID: "0123456789",
					Region:     "us-west-2",
					Name:       "test-repo",
					Tag:        "digest-value",
				},
				ImageLabel:                "label of image",
				ScanFindings:              types.ImageScanFindings{},
				CriticalSeverityThreshold: 0,
				HighSeverityThreshold:     0,
			},
		},
		{
			name: "findings included",
			data: report.AnnotationContext{
				Image: registry.RegistryInfo{
					RegistryID: "0123456789",
					Region:     "us-west-2",
					Name:       "test-repo",
					Tag:        "digest-value",
				},
				ImageLabel: "label of image",
				ScanFindings: types.ImageScanFindings{
					FindingSeverityCounts: map[string]int32{
						"HIGH": 1,
					},
					Findings: []types.ImageScanFinding{
						{
							Name:        aws.String("CVE-2019-5188"),
							Description: aws.String("A code execution vulnerability exists in the directory rehashing functionality of E2fsprogs e2fsck 1.45.4. A specially crafted ext4 directory can cause an out-of-bounds write on the stack, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability."),
							Uri:         aws.String("http://people.ubuntu.com/~ubuntu-security/cve/CVE-2019-5188"),
							Severity:    "HIGH",
							Attributes: []types.Attribute{
								{
									Key:   aws.String("package_version"),
									Value: aws.String("1.44.1-1ubuntu1.1"),
								},
								{
									Key:   aws.String("package_name"),
									Value: aws.String("e2fsprogs"),
								},
								{
									Key:   aws.String("CVSS2_VECTOR"),
									Value: aws.String("AV:L/AC:L/Au:N/C:P/I:P/A:P"),
								},
								{
									Key:   aws.String("CVSS2_SCORE"),
									Value: aws.String("4.6"),
								},
							},
						},
					},
				},
				CriticalSeverityThreshold: 0,
				HighSeverityThreshold:     0,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fmt.Println(c.name, t.Name())
			result, err := c.data.Render()

			testza.AssertNoError(t, err)
			err = testza.SnapshotCreateOrValidate(t, t.Name(), string(result))
			testza.AssertNoError(t, err)
		})
	}
}

func TestReportRender(t *testing.T) {
	data := report.AnnotationContext{
		Image: registry.RegistryInfo{
			RegistryID: "0123456789",
			Region:     "us-west-2",
			Name:       "test-repo",
			Tag:        "digest-value",
		},
		ImageLabel: "windowsservercore-ltsc2022",
		ScanFindings: types.ImageScanFindings{
			FindingSeverityCounts: map[string]int32{
				"HIGH": 1,
			},
			Findings: []types.ImageScanFinding{
				{
					Name:        aws.String("CVE-2019-5188"),
					Description: aws.String("A code execution vulnerability exists in the directory rehashing functionality of E2fsprogs e2fsck 1.45.4. A specially crafted ext4 directory can cause an out-of-bounds write on the stack, resulting in code execution. An attacker can corrupt a partition to trigger this vulnerability."),
					Uri:         aws.String("http://people.ubuntu.com/~ubuntu-security/cve/CVE-2019-5188"),
					Severity:    "HIGH",
					Attributes: []types.Attribute{
						{
							Key:   aws.String("package_version"),
							Value: aws.String("1.44.1-1ubuntu1.1"),
						},
						{
							Key:   aws.String("package_name"),
							Value: aws.String("e2fsprogs"),
						},
						{
							Key:   aws.String("CVSS2_VECTOR"),
							Value: aws.String("AV:L/AC:L/Au:N/C:P/I:P/A:P"),
						},
						{
							Key:   aws.String("CVSS2_SCORE"),
							Value: aws.String("4.6"),
						},
					},
				},
			},
		},
		CriticalSeverityThreshold: 0,
		HighSeverityThreshold:     0,
	}

	result, err := data.Render()
	os.WriteFile("./testdata/render.html", result, 0644)

	testza.AssertNoError(t, err)
}
