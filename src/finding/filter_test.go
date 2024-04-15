package finding_test

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/buildkite/ecrscanresults/src/finding"
	"github.com/stretchr/testify/assert"
)

func TestFilterFindings(t *testing.T) {
	sampleFindings := finding.Summary{
		Details: []finding.Detail{
			{
				Name:     "cve-1",
				Severity: types.FindingSeverityLow,
			},
			{
				Name:     "cve-2",
				Severity: types.FindingSeverityMedium,
			},
			{
				Name:     "cve-3",
				Severity: types.FindingSeverityHigh,
			},
			{
				Name:     "cve-4",
				Severity: types.FindingSeverityHigh,
			},
		},
	}

	type args struct {
		summary finding.Summary
		filters []finding.Filter
	}
	tests := []struct {
		name   string
		args   args
		wantFn func(finding.Summary) bool
	}{
		{
			name: "keep all",
			args: args{
				summary: sampleFindings,
				filters: []finding.Filter{
					func(finding.Detail) bool { return true },
				},
			},
			wantFn: func(sf finding.Summary) bool {
				return len(sf.Details) == len(sampleFindings.Details)
			},
		},
		{
			name: "skip all",
			args: args{
				summary: sampleFindings,
				filters: []finding.Filter{
					func(finding.Detail) bool { return false },
				},
			},
			wantFn: func(sf finding.Summary) bool {
				return len(sf.Details) == 0
			},
		},
		{
			name: "ignore cev-2",
			args: args{
				summary: sampleFindings,
				filters: []finding.Filter{
					finding.FilterIgnoredNames([]string{"cve-2"}),
				},
			},
			wantFn: func(sf finding.Summary) bool {
				return len(sf.Details) == 3
			},
		},
		{
			name: "sev high+",
			args: args{
				summary: sampleFindings,
				filters: []finding.Filter{
					finding.FilterMinSeverity(types.FindingSeverityHigh),
				},
			},
			wantFn: func(sf finding.Summary) bool {
				return len(sf.Details) == 2 && sf.Counts["HIGH"].Included == 2
			},
		},
		{
			name: "multiple filters",
			args: args{
				summary: sampleFindings,
				filters: []finding.Filter{
					finding.FilterMinSeverity(types.FindingSeverityHigh),
					func(finding.Detail) bool { return false },
				},
			},
			wantFn: func(sf finding.Summary) bool {
				return len(sf.Details) == 0
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := finding.FilterSummary(tt.args.summary, tt.args.filters...)
			assert.True(t, tt.wantFn(got))
		})
	}
}
