package listsources

import (
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/utils"
)

// Return a channel that notifies each file in the path that doesn't match the filter rules.
func ListSourcesForPath(path string, logger *zerolog.Logger, max_threads int) (<-chan string, error) {
	filter := utils.NewFileFilter(path, logger, utils.WithThreadNumber(max_threads))
	rules, err := filter.GetRules([]string{".gitignore", ".dcignore", ".snyk"})
	if err != nil {
		return nil, err
	}

	results := filter.GetFilteredFiles(filter.GetAllFiles(), rules)
	return results, nil
}
