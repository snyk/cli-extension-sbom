package util_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/constants"
	"github.com/snyk/cli-extension-sbom/internal/util"
)

func TestHasUvLockFile(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("does not find uv.lock file when all-projects flag is set to false and uv.lock file exists in subfolder", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir, "project1")

		result := util.HasUvLockFile(tmpDir, "", false, &nopLogger)
		assert.False(t, result)
	})

	t.Run("does find uv.lock file when all-projects flag is set to true and uv.lock file exists in subfolder", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir, "project1")

		result := util.HasUvLockFile(tmpDir, "", true, &nopLogger)
		assert.True(t, result)
	})
}

func TestHasUvLockFileSingle(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("returns true when uv.lock exists", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir)

		result := util.HasUvLockFileSingle(tmpDir, "", &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when uv.lock exists with target file", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir)

		result := util.HasUvLockFileSingle(tmpDir, "uv.lock", &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when uv.lock exists with target file in subdirectory", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir, "subdir")

		result := util.HasUvLockFileSingle(tmpDir, "subdir/uv.lock", &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when uv.lock exists with target file in subdirectory and giving absolute path", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir, "subdir")
		absolutePath := filepath.Join(tmpDir, "subdir", constants.UvLockFileName)

		result := util.HasUvLockFileSingle(tmpDir, absolutePath, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns false when uv.lock does not exist", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		result := util.HasUvLockFileSingle(dir, "", &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false when directory does not exist", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "nonexistent")

		result := util.HasUvLockFileSingle(dir, "", &nopLogger)
		assert.False(t, result)
	})

	t.Run("works with nil logger", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		uvLockPath := filepath.Join(dir, constants.UvLockFileName)
		err := os.WriteFile(uvLockPath, []byte("# test"), 0o600)
		require.NoError(t, err)

		result := util.HasUvLockFileSingle(dir, "", nil)
		assert.True(t, result)
	})
}

func TestHasUvLockFileRecursive(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("returns true when uv.lock exists", func(t *testing.T) {
		t.Parallel()

		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir)

		result := util.HasUvLockFileRecursive(tmpDir, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when uv.lock exists in subdirectory", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir, "subdir")

		result := util.HasUvLockFileRecursive(tmpDir, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns false when uv.lock exists in excluded subdirectory", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		createUvLockFile(t, tmpDir, "node_modules")
		createUvLockFile(t, tmpDir, "subdir", "node_modules")
		createUvLockFile(t, tmpDir, ".build")

		result := util.HasUvLockFileRecursive(tmpDir, &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false when uv.lock does not exist", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()

		result := util.HasUvLockFileRecursive(dir, &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false when directory does not exist", func(t *testing.T) {
		t.Parallel()
		dir := filepath.Join(t.TempDir(), "nonexistent")

		result := util.HasUvLockFileRecursive(dir, &nopLogger)
		assert.False(t, result)
	})

	t.Run("works with nil logger", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		uvLockPath := filepath.Join(dir, constants.UvLockFileName)
		err := os.WriteFile(uvLockPath, []byte("# test"), 0o600)
		require.NoError(t, err)

		result := util.HasUvLockFileRecursive(dir, nil)
		assert.True(t, result)
	})
}

func TestHasUvLockFileInAnyDir(t *testing.T) {
	t.Parallel()
	nopLogger := zerolog.Nop()

	t.Run("returns true when first directory has uv.lock", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		dir2 := t.TempDir()

		uvLockPath := filepath.Join(dir1, constants.UvLockFileName)
		err := os.WriteFile(uvLockPath, []byte("# test"), 0o600)
		require.NoError(t, err)

		result := util.HasUvLockFileInAnyDir([]string{dir1, dir2}, "", false, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when second directory has uv.lock", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		dir2 := t.TempDir()

		uvLockPath := filepath.Join(dir2, constants.UvLockFileName)
		err := os.WriteFile(uvLockPath, []byte("# test"), 0o600)
		require.NoError(t, err)

		result := util.HasUvLockFileInAnyDir([]string{dir1, dir2}, "", false, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns true when multiple directories have uv.lock", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		dir2 := t.TempDir()

		uvLockPath1 := filepath.Join(dir1, constants.UvLockFileName)
		err := os.WriteFile(uvLockPath1, []byte("# test"), 0o600)
		require.NoError(t, err)

		uvLockPath2 := filepath.Join(dir2, constants.UvLockFileName)
		err = os.WriteFile(uvLockPath2, []byte("# test"), 0o600)
		require.NoError(t, err)

		result := util.HasUvLockFileInAnyDir([]string{dir1, dir2}, "", false, &nopLogger)
		assert.True(t, result)
	})

	t.Run("returns false when no directories have uv.lock", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		dir2 := t.TempDir()

		result := util.HasUvLockFileInAnyDir([]string{dir1, dir2}, "", false, &nopLogger)
		assert.False(t, result)
	})

	t.Run("returns false for empty directory list", func(t *testing.T) {
		t.Parallel()

		result := util.HasUvLockFileInAnyDir([]string{}, "", false, &nopLogger)
		assert.False(t, result)
	})

	t.Run("handles mix of existing and non-existing directories", func(t *testing.T) {
		t.Parallel()
		dir1 := t.TempDir()
		nonExistentDir := filepath.Join(t.TempDir(), "nonexistent")

		uvLockPath := filepath.Join(dir1, constants.UvLockFileName)
		err := os.WriteFile(uvLockPath, []byte("# test"), 0o600)
		require.NoError(t, err)

		result := util.HasUvLockFileInAnyDir([]string{nonExistentDir, dir1}, "", false, &nopLogger)
		assert.True(t, result)
	})
}

func createUvLockFile(t *testing.T, rootDir string, subFolders ...string) {
	t.Helper()

	uvLockDir := filepath.Join(append([]string{rootDir}, subFolders...)...)
	err := os.MkdirAll(uvLockDir, 0o755)
	require.NoError(t, err)

	uvLockPath := filepath.Join(uvLockDir, constants.UvLockFileName)
	err = os.WriteFile(uvLockPath, []byte("# test"), 0o600)
	require.NoError(t, err)
}
