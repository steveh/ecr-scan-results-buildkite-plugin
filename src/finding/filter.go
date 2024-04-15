package finding

import (
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

type Filter = func(Detail) bool

func FilterSummary(unfilteredSummary Summary, filters ...Filter) Summary {
	filteredSummary := Summary{
		Counts:                       make(map[types.FindingSeverity]SeverityCount),
		ImageScanCompletedAt:         unfilteredSummary.ImageScanCompletedAt,
		VulnerabilitySourceUpdatedAt: unfilteredSummary.VulnerabilitySourceUpdatedAt,
		Platforms:                    unfilteredSummary.Platforms,
		FailedPlatforms:              unfilteredSummary.FailedPlatforms,
	}

	for _, det := range unfilteredSummary.Details {
		keep := true

		for _, filter := range filters {
			if !filter(det) {
				keep = false
				break
			}
		}

		if keep {
			filteredSummary.Details = append(filteredSummary.Details, det)

			counts := filteredSummary.Counts[det.Severity]
			counts.Included++

			filteredSummary.Counts[det.Severity] = counts
		}
	}

	return filteredSummary
}

func FilterIgnoredNames(namesToIgnore []string) Filter {
	return func(det Detail) bool {
		return !slices.Contains(namesToIgnore, det.Name)
	}
}

func FilterMinSeverity(minSeverity types.FindingSeverity) Filter {
	return func(det Detail) bool {
		return severityLevel(det.Severity) >= severityLevel(minSeverity)
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
