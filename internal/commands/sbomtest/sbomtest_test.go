package sbomtest_test

import (
	"errors"
	"io"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	snyk_errors "github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbomtest"
	"github.com/snyk/cli-extension-sbom/internal/flags"
)

func TestSBOMTestWorkflow_NoFileFlag(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)

	mockICTX := mockInvocationContext(t, ctrl, mockEngine)

	_, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "Flag `--file` is required to execute this command. Value should point to a valid SBOM document.")
}

func TestSBOMTestWorkflow_InvalidFilePath(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)

	mockICTX := mockInvocationContext(t, ctrl, mockEngine)
	mockICTX.GetConfiguration().Set("file", "missing-file.txt")

	_, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	var snykErr snyk_errors.Error
	require.True(t, errors.As(err, &snykErr))
	assert.Equal(t, "Invalid flag option", snykErr.Title)
	assert.Equal(t, `The given filepath "missing-file.txt" does not exist.`, snykErr.Detail)
}

func TestSBOMTestWorkflow_DelegatesToOSF(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)

	mockICTX := mockInvocationContext(t, ctrl, mockEngine)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")

	osFlowsTestConfig := mockICTX.GetConfiguration().Clone()
	osFlowsTestConfig.Set(flags.FlagSBOM, "testdata/bom.json")

	mockEngine.EXPECT().InvokeWithConfig(sbomtest.OsFlowsTestWorkflowID, osFlowsTestConfig).Return([]workflow.Data{}, nil).Times(1)

	result, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestSBOMTestWorkflow_PassesConfigToOSF(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)

	mockICTX := mockInvocationContext(t, ctrl, mockEngine)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")
	mockICTX.GetConfiguration().Set(flags.FlagReachability, true)

	osFlowsTestConfig := mockICTX.GetConfiguration().Clone()
	osFlowsTestConfig.Set(flags.FlagReachability, true)
	osFlowsTestConfig.Set(flags.FlagSBOM, "testdata/bom.json")

	mockEngine.EXPECT().InvokeWithConfig(sbomtest.OsFlowsTestWorkflowID, osFlowsTestConfig).Return([]workflow.Data{}, nil).Times(1)

	result, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestSBOMTestWorkflow_ReportFlag_FFEnabled_DelegatesToOSF(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)

	mockICTX := mockInvocationContext(t, ctrl, mockEngine)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")
	mockICTX.GetConfiguration().Set(flags.FlagReport, true)
	mockICTX.GetConfiguration().Set(sbomtest.FeatureFlagDflySbomMonitor, true)
	mockICTX.GetConfiguration().Set(flags.FlagAssetName, "my-asset")

	osFlowsTestConfig := mockICTX.GetConfiguration().Clone()
	osFlowsTestConfig.Set(flags.FlagSBOM, "testdata/bom.json")

	mockEngine.EXPECT().InvokeWithConfig(sbomtest.OsFlowsTestWorkflowID, osFlowsTestConfig).Return([]workflow.Data{}, nil).Times(1)

	result, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestSBOMTestWorkflow_ReportFlag_FFEnabled_NoAssetName_ReturnsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)

	mockICTX := mockInvocationContext(t, ctrl, mockEngine)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")
	mockICTX.GetConfiguration().Set(flags.FlagReport, true)
	mockICTX.GetConfiguration().Set(sbomtest.FeatureFlagDflySbomMonitor, true)

	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any()).Times(0)

	_, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	require.Error(t, err)
	assert.ErrorContains(t, err, "Flag `--asset-name` is required when using `--report`.")
}

func TestSBOMTestWorkflow_ReportFlag_FFEnabled_EmptyAssetName_ReturnsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)

	mockICTX := mockInvocationContext(t, ctrl, mockEngine)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")
	mockICTX.GetConfiguration().Set(flags.FlagReport, true)
	mockICTX.GetConfiguration().Set(sbomtest.FeatureFlagDflySbomMonitor, true)
	mockICTX.GetConfiguration().Set(flags.FlagAssetName, "")

	mockEngine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any()).Times(0)

	_, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	require.Error(t, err)
	assert.ErrorContains(t, err, "Flag `--asset-name` is required when using `--report`.")
}

func TestSBOMTestWorkflow_NoReportFlag_NoAssetName_DelegatesToOSF(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)

	mockICTX := mockInvocationContext(t, ctrl, mockEngine)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")
	mockICTX.GetConfiguration().Set(sbomtest.FeatureFlagDflySbomMonitor, true)

	osFlowsTestConfig := mockICTX.GetConfiguration().Clone()
	osFlowsTestConfig.Set(flags.FlagSBOM, "testdata/bom.json")

	mockEngine.EXPECT().InvokeWithConfig(sbomtest.OsFlowsTestWorkflowID, osFlowsTestConfig).Return([]workflow.Data{}, nil).Times(1)

	result, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestSBOMTestWorkflow_ReportFlag_FFDisabled_ReturnsError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)

	mockICTX := mockInvocationContext(t, ctrl, mockEngine)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")
	mockICTX.GetConfiguration().Set(flags.FlagReport, true)

	_, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "not available for your organization")
}

func TestSBOMTestWorkflow_ReportFlagUnset_FFDisabled_DelegatesToOSF(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)

	mockICTX := mockInvocationContext(t, ctrl, mockEngine)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")

	osFlowsTestConfig := mockICTX.GetConfiguration().Clone()
	osFlowsTestConfig.Set(flags.FlagSBOM, "testdata/bom.json")

	mockEngine.EXPECT().InvokeWithConfig(sbomtest.OsFlowsTestWorkflowID, osFlowsTestConfig).Return([]workflow.Data{}, nil).Times(1)

	result, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestSBOMTestWorkflow_AssetName_CarriedThroughToOSF(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)

	mockICTX := mockInvocationContext(t, ctrl, mockEngine)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")
	mockICTX.GetConfiguration().Set(flags.FlagAssetName, "my-asset")

	var forwardedConfig configuration.Configuration
	mockEngine.EXPECT().
		InvokeWithConfig(sbomtest.OsFlowsTestWorkflowID, gomock.Any()).
		DoAndReturn(func(_ workflow.Identifier, cfg configuration.Configuration) ([]workflow.Data, error) {
			forwardedConfig = cfg
			return []workflow.Data{}, nil
		}).
		Times(1)

	result, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, forwardedConfig, "expected the workflow to forward a config to the os-flows test workflow")
	assert.Equal(t, "my-asset", forwardedConfig.GetString(flags.FlagAssetName), "--asset-name should be forwarded to the os-flows test workflow")
	assert.Equal(t, "testdata/bom.json", forwardedConfig.GetString(flags.FlagSBOM), "--sbom should be derived from --file when forwarding")
}

func TestSBOMTestWorkflow_ExperimentalFlagIgnored(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockEngine := mocks.NewMockEngine(ctrl)

	mockICTX := mockInvocationContext(t, ctrl, mockEngine)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")
	mockICTX.GetConfiguration().Set(flags.FlagExperimental, true)

	osFlowsTestConfig := mockICTX.GetConfiguration().Clone()
	osFlowsTestConfig.Set(flags.FlagSBOM, "testdata/bom.json")

	mockEngine.EXPECT().InvokeWithConfig(sbomtest.OsFlowsTestWorkflowID, osFlowsTestConfig).Return([]workflow.Data{}, nil).Times(1)

	result, err := sbomtest.TestWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)
	require.NotNil(t, result)
}

// Helpers

func mockInvocationContext(
	t *testing.T,
	ctrl *gomock.Controller,
	mockEngine *mocks.MockEngine,
) workflow.InvocationContext {
	t.Helper()

	mockLogger := zerolog.New(io.Discard)

	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<SOME API TOKEN>")
	mockConfig.Set(configuration.ORGANIZATION, "6277734c-fc84-4c74-9662-33d46ec66c53")
	mockConfig.Set(configuration.API_URL, "")
	mockConfig.Set("format", "cyclonedx1.4+json")
	mockConfig.Set("name", "goof")
	mockConfig.Set("version", "0.0.0")

	mockRuntimeInfo := runtimeinfo.New(
		runtimeinfo.WithName("test-app"),
		runtimeinfo.WithVersion("1.2.3"))

	ictx := mocks.NewMockInvocationContext(ctrl)
	ictx.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	ictx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	ictx.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(mockConfig)).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&mockLogger).AnyTimes()
	ictx.EXPECT().GetRuntimeInfo().Return(mockRuntimeInfo).AnyTimes()

	return ictx
}
