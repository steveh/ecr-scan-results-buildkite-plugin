package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfigWithYAMLFile(t *testing.T) {
	t.Setenv("IMAGE_NAME", "buildkite")
	t.Setenv("IGNORE_FILE", "testdata/ignored.yml")
	config, err := parseConfig()
	require.NoError(t, err)
	assert.ElementsMatch(t, config.IgnoredVulnerabilities, []string{"CVE-2023-12345", "CVE-2022-9876"})
}

func TestParseConfigMergeIgnoredCVEs(t *testing.T) {
	t.Setenv("IMAGE_NAME", "buildkite")
	t.Setenv("IGNORE_FILE", "testdata/ignored.yml")
	t.Setenv("IGNORE", "CVE-2023-111")
	config, err := parseConfig()
	require.NoError(t, err)
	assert.ElementsMatch(t, config.IgnoredVulnerabilities, []string{"CVE-2023-111", "CVE-2023-12345", "CVE-2022-9876"})
}

func TestParseConfigMergeWithoutDuplicates(t *testing.T) {
	t.Setenv("IMAGE_NAME", "buildkite")
	t.Setenv("IGNORE_FILE", "testdata/ignored.yml")
	t.Setenv("IGNORE", "CVE-2023-111,CVE-2023-12345")
	config, err := parseConfig()
	require.NoError(t, err)
	assert.ElementsMatch(t, config.IgnoredVulnerabilities, []string{"CVE-2023-111", "CVE-2023-12345", "CVE-2022-9876"})
}

func TestParseConfigWithoutYAMLFile(t *testing.T) {
	t.Setenv("IMAGE_NAME", "buildkite")
	t.Setenv("IGNORE_FILE", "testdata/not_such_file")
	_, err := parseConfig()
	require.NoError(t, err)
}
