package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/justincampbell/timeago"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/buildkite/ecrscanresults/src/registry"
)

//go:embed annotation.gohtml
var annotationTemplateSource string

type AnnotationContext struct {
	Image                     registry.RegistryInfo
	ImageLabel                string
	ScanFindings              types.ImageScanFindings
	CriticalSeverityThreshold int32
	HighSeverityThreshold     int32
	Help                      string
}

func (c AnnotationContext) Render() ([]byte, error) {
	t, err := template.
		New("annotation").
		Funcs(template.FuncMap{
			"titleCase": func(s string) string {
				c := cases.Title(language.English)
				return c.String(s)
			},
			"lowerCase":        strings.ToLower,
			"findingAttribute": findingAttributeValue,
			"nbsp": func(input string) any {
				if len(input) > 0 {
					return input
				} else {
					return template.HTML(`&nbsp;`)
				}
			},
			"timeAgo": func(tm *time.Time) string {
				if tm == nil {
					return ""
				}

				return timeago.FromTime(*tm)
			},
			"string": func(input any) (string, error) {
				if strg, ok := input.(fmt.Stringer); ok {
					return strg.String(), nil
				}

				return fmt.Sprintf("%s", input), nil
			},
		}).
		Parse(annotationTemplateSource)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	err = t.Execute(&buf, c)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func findingAttributeValue(name string, finding types.ImageScanFinding) string {
	for _, a := range finding.Attributes {
		if aws.ToString(a.Key) == name {
			return aws.ToString(a.Value)
		}
	}
	return ""
}
