package util

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/snyk/cli-extension-sbom/internal/constants"
)

const logKeyPath = "path"

// ExcludedUVLockFileDirs is a list of directories that are excluded from the uv.lock file search.
var ExcludedUVLockFileDirs = map[string]bool{
	"node_modules": true,
	".build":       true,
}

// HasUvLockFile checks if the specified directory contains a uv.lock file or the target file if provided.
// If allProjects is true, the function will check if the directory contains a uv.lock file recursively.
// Otherwise, it will only check if the directory contains a uv.lock file.
func HasUvLockFile(dir, targetFile string, allProjects bool, logger *zerolog.Logger) bool {
	if allProjects {
		return HasUvLockFileRecursive(dir, logger)
	}
	return HasUvLockFileSingle(dir, targetFile, logger)
}

// HasUvLockFileSingle checks if the specified directory contains a uv.lock file or the target file if provided.
// If targetFile is an absolute path, it will be used directly; otherwise, it will be joined with dir.
func HasUvLockFileSingle(dir, targetFile string, logger *zerolog.Logger) bool {
	var uvLockPath string
	if targetFile != "" {
		if filepath.IsAbs(targetFile) {
			uvLockPath = targetFile
		} else {
			uvLockPath = filepath.Join(dir, targetFile)
		}
	} else {
		uvLockPath = filepath.Join(dir, constants.UvLockFileName)
	}

	_, err := os.Stat(uvLockPath)
	if err == nil {
		return true
	}

	if !errors.Is(err, os.ErrNotExist) && logger != nil {
		logger.Debug().
			Err(err).
			Str("path", uvLockPath).
			Msg("Error checking for uv.lock file")
	}

	return false
}

// HasUvLockFileRecursive checks if any directory within dir (including dir itself)
// contains a uv.lock file, skipping directories in ExcludedUVLockFileDirs.
func HasUvLockFileRecursive(dir string, logger *zerolog.Logger) bool {
	found := false
	fpErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if logger != nil {
				logger.Debug().
					Err(err).
					Str(logKeyPath, path).
					Msg("Error accessing path during uv.lock search")
			}
			return nil // Continue walking despite errors
		}

		// Skip excluded directories
		if d.IsDir() {
			dirName := d.Name()
			if ExcludedUVLockFileDirs[dirName] {
				if logger != nil {
					logger.Debug().
						Str(logKeyPath, path).
						Msg("Skipping excluded directory during uv.lock search")
				}
				return fs.SkipDir
			}
			return nil
		}

		if d.Name() == constants.UvLockFileName {
			found = true
			return fs.SkipAll // Stop walking, we found what we're looking for
		}

		return nil
	})

	if fpErr != nil && logger != nil {
		logger.Debug().
			Err(fpErr).
			Str(logKeyPath, dir).
			Msg("Error checking for uv.lock file")
	}

	return found
}

// HasUvLockFileInAnyDir checks if any of the input directories contains a uv.lock file.
func HasUvLockFileInAnyDir(inputDirs []string, targetFile string, allProjects bool, logger *zerolog.Logger) bool {
	for _, inputDir := range inputDirs {
		if HasUvLockFile(inputDir, targetFile, allProjects, logger) {
			return true
		}
	}
	return false
}
