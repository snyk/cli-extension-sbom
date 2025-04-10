package sbommonitor

import (
	"fmt"
	"strings"

	"github.com/snyk/cli-extension-sbom/internal/snykclient"
)

func concatConversionWarnings(warnings []*snykclient.ConversionWarning) string {
	sb := strings.Builder{}
	for _, warn := range warnings {
		var suffix string
		if warn.BOMRef != "" {
			suffix = fmt.Sprintf(" (%s)", warn.BOMRef)
		}
		sb.WriteString(fmt.Sprintf("WARNING: [%s] %s%s\n", warn.Type, warn.Msg, suffix))
	}
	return sb.String()
}
