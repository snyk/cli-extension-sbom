package constants

// FeatureFlagUvCLI is used to gate uv support in the CLI.
const FeatureFlagUvCLI = "internal_snyk_cli_uv_enabled"

// UvLockFileName is the name of the uv lock file.
const UvLockFileName = "uv.lock"

// FeatureFlagShowMavenBuildScope is to gate the maven build scope feature.
const FeatureFlagShowMavenBuildScope = "internal_snyk_show_maven_scope_enabled"

// ShowMavenBuildScope is the feature flag name for the maven build scope feature.
const ShowMavenBuildScope = "show-maven-build-scope"

// FeatureFlagShowNpmScope is to gate the npm build scope feature.
const FeatureFlagShowNpmScope = "internal_snyk_show_npm_scope_enabled"

// ShowNpmScope is the feature flag name for the npm build scope feature.
const ShowNpmScope = "show-npm-scope"
