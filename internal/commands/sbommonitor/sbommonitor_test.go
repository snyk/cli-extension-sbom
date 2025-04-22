package sbommonitor_test

import (
	"bytes"
	_ "embed"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-sbom/internal/commands/sbommonitor"
	"github.com/snyk/cli-extension-sbom/internal/flags"
	svcmocks "github.com/snyk/cli-extension-sbom/internal/mocks"
)

//go:embed testdata/sbom-test-convert.response.json
var testResultMockResponse []byte

//go:embed testdata/sbom-test-convert-project-with-warnings.response.json
var testResultMockResponseWithWarnings []byte

//go:embed testdata/sbom-test-convert-no-results.response.json
var testNoResultMockResponse []byte

//go:embed testdata/registry-monitor-dependencies.response.json
var monitorDependenciesResultMockResponse []byte

//go:embed testdata/registry-monitor-dependencies.response2.json
var monitorDependenciesResultMockResponse2 []byte

var snapshotter = cupaloy.New(cupaloy.SnapshotSubdirectory("testdata/snapshots"))

func TestSBOMMonitorWorkflow_NoExperimentalFlag(t *testing.T) {
	mockICTX := createMockICTX(t)

	_, err := sbommonitor.MonitorWorkflow(mockICTX, []workflow.Data{})

	assert.ErrorContains(t, err, "Flag `--experimental` is required to execute this command.")
}

func TestSBOMMonitorWorkflow_NoRemoteRepoURL(t *testing.T) {
	mockICTX := createMockICTX(t)
	mockICTX.GetConfiguration().Set("experimental", true)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")
	mockICTX.GetConfiguration().Set(sbommonitor.FeatureFlagSBOMMonitor, true)

	g := &GitStub{remoteOriginURL: ""}

	_, err := sbommonitor.MonitorWorkflowWithDI(mockICTX, []workflow.Data{}, g)

	assert.ErrorContains(t, err, "Can't determine remote URL automatically, please set a remote URL with `--remote-repo-url` flag.")
}

func TestSBOMMonitorWorkflow_Success(t *testing.T) {
	remoteGitURL := "https://example.com/flag-url"

	responses := []svcmocks.MockResponse{
		svcmocks.NewMockResponse("application/vnd.api+json", testResultMockResponse, http.StatusOK),
		svcmocks.NewMockResponse("application/vnd.api+json", monitorDependenciesResultMockResponse, http.StatusOK),
	}

	var monitorDependenciesRequestBody string

	mockSBOMService := svcmocks.NewMockSBOMServiceMultiResponse(responses, func(r *http.Request) {
		if strings.Contains(r.RequestURI, "monitor-dependencies") {
			var err error
			monitorDependenciesRequestBody, err = processRequest(r)
			require.NoError(t, err)
		}
	})
	defer mockSBOMService.Close()

	mockICTX := createMockICTXWithURL(t, mockSBOMService.URL)
	mockICTX.GetConfiguration().Set("experimental", true)
	mockICTX.GetConfiguration().Set(sbommonitor.FeatureFlagSBOMMonitor, true)
	mockICTX.GetConfiguration().Set(flags.FlagRemoteRepoURL, remoteGitURL)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")

	data, err := sbommonitor.MonitorWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)

	assert.Contains(t, monitorDependenciesRequestBody, remoteGitURL, "Request body should contain remote repo URL")
	snapshotter.SnapshotT(t, data[0].GetPayload())
}

func TestSBOMMonitorWorkflow_Success_WithWarnings(t *testing.T) {
	remoteGitURL := "https://example.com/flag-url"

	responses := []svcmocks.MockResponse{
		svcmocks.NewMockResponse("application/vnd.api+json", testResultMockResponseWithWarnings, http.StatusOK),
		svcmocks.NewMockResponse("application/vnd.api+json", monitorDependenciesResultMockResponse, http.StatusOK),
		svcmocks.NewMockResponse("application/vnd.api+json", monitorDependenciesResultMockResponse2, http.StatusOK),
	}

	var monitorDependenciesRequestBody string

	mockSBOMService := svcmocks.NewMockSBOMServiceMultiResponse(responses, func(r *http.Request) {
		if strings.Contains(r.RequestURI, "monitor-dependencies") {
			var err error
			monitorDependenciesRequestBody, err = processRequest(r)
			require.NoError(t, err)
		}
	})
	defer mockSBOMService.Close()

	mockICTX := createMockICTXWithURL(t, mockSBOMService.URL)
	mockICTX.GetConfiguration().Set("experimental", true)
	mockICTX.GetConfiguration().Set(sbommonitor.FeatureFlagSBOMMonitor, true)
	mockICTX.GetConfiguration().Set(flags.FlagRemoteRepoURL, remoteGitURL)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")

	data, err := sbommonitor.MonitorWorkflow(mockICTX, []workflow.Data{})

	require.NoError(t, err)

	assert.Contains(t, monitorDependenciesRequestBody, remoteGitURL, "Request body should contain remote repo URL")
	snapshotter.SnapshotT(t, data[0].GetPayload())
}

func TestSBOMMonitor_RemoteRepoURL(t *testing.T) {
	testTable := []struct {
		testName string

		flagUrl           string
		gitUrl            string
		expectedRemoteUrl string
	}{
		{
			testName:          "flag URL but no git URL",
			flagUrl:           "https://example.com/flag-url",
			gitUrl:            "",
			expectedRemoteUrl: "https://example.com/flag-url",
		},
		{
			testName:          "git URL but no flag URL",
			flagUrl:           "",
			gitUrl:            "https://example.com/git-url",
			expectedRemoteUrl: "https://example.com/git-url",
		},
		{
			testName:          "flag URL overrides git URL",
			flagUrl:           "https://example.com/flag-url",
			gitUrl:            "https://example.com/git-url",
			expectedRemoteUrl: "https://example.com/flag-url",
		},
	}

	responses := []svcmocks.MockResponse{
		svcmocks.NewMockResponse("application/vnd.api+json", testResultMockResponse, http.StatusOK),
		svcmocks.NewMockResponse("application/vnd.api+json", monitorDependenciesResultMockResponse, http.StatusOK),
	}

	for _, testCase := range testTable {
		t.Run(testCase.testName, func(t *testing.T) {
			var monitorDependenciesRequestBody string

			mockSBOMService := svcmocks.NewMockSBOMServiceMultiResponse(responses, func(r *http.Request) {
				if strings.Contains(r.RequestURI, "monitor-dependencies") {
					var err error
					monitorDependenciesRequestBody, err = processRequest(r)
					require.NoError(t, err)
				}
			})
			defer mockSBOMService.Close()

			mockICTX := createMockICTXWithURL(t, mockSBOMService.URL)
			mockICTX.GetConfiguration().Set("experimental", true)
			mockICTX.GetConfiguration().Set(sbommonitor.FeatureFlagSBOMMonitor, true)
			mockICTX.GetConfiguration().Set(flags.FlagRemoteRepoURL, testCase.flagUrl)
			mockICTX.GetConfiguration().Set("file", "testdata/bom.json")

			gitStub := &GitStub{remoteOriginURL: testCase.gitUrl}
			_, err := sbommonitor.MonitorWorkflowWithDI(mockICTX, []workflow.Data{}, gitStub)

			require.NoError(t, err)

			assert.Contains(t, monitorDependenciesRequestBody, testCase.expectedRemoteUrl, "Request body should contain remote repo URL")
		})
	}
}

// Helpers

type GitStub struct {
	remoteOriginURL string
}

func (g *GitStub) GetRemoteOriginURL() string {
	return g.remoteOriginURL
}

func TestSBOMMonitorWorkflow_NoTestableProjects(t *testing.T) {
	remoteGitURL := "https://example.com/flag-url"

	responses := []svcmocks.MockResponse{
		svcmocks.NewMockResponse("application/vnd.api+json", testNoResultMockResponse, http.StatusOK),
		svcmocks.NewMockResponse("application/vnd.api+json", monitorDependenciesResultMockResponse, http.StatusOK),
	}

	mockSBOMService := svcmocks.NewMockSBOMServiceMultiResponse(responses, func(r *http.Request) {})
	defer mockSBOMService.Close()

	mockICTX := createMockICTXWithURL(t, mockSBOMService.URL)
	mockICTX.GetConfiguration().Set("experimental", true)
	mockICTX.GetConfiguration().Set(sbommonitor.FeatureFlagSBOMMonitor, true)
	mockICTX.GetConfiguration().Set(flags.FlagRemoteRepoURL, remoteGitURL)
	mockICTX.GetConfiguration().Set("file", "testdata/bom.json")

	_, err := sbommonitor.MonitorWorkflow(mockICTX, []workflow.Data{})

	require.Error(t, err, "WARNING: [NoComponents] This is a warning\n"+"No supported projects were found in the SBOM you are trying to monitor. "+
		"Please check that your SBOM contains supported ecosystems and dependency relationships.")
}

func processRequest(r *http.Request) (string, error) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}

	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	bodyString := string(bodyBytes)
	return bodyString, nil
}

func createMockICTX(t *testing.T) workflow.InvocationContext {
	t.Helper()

	return createMockICTXWithURL(t, "")
}

func createMockICTXWithURL(t *testing.T, sbomServiceURL string) workflow.InvocationContext {
	t.Helper()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	return mockInvocationContext(t, ctrl, sbomServiceURL, nil)
}

func mockInvocationContext(
	t *testing.T,
	ctrl *gomock.Controller,
	sbomServiceURL string,
	mockEngine *mocks.MockEngine,
) workflow.InvocationContext {
	t.Helper()

	mockLogger := log.New(io.Discard, "", 0)

	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<SOME API TOKEN>")
	mockConfig.Set(configuration.ORGANIZATION, "6277734c-fc84-4c74-9662-33d46ec66c53")
	mockConfig.Set(configuration.API_URL, sbomServiceURL)

	mockRuntimeInfo := runtimeinfo.New(
		runtimeinfo.WithName("test-app"),
		runtimeinfo.WithVersion("1.2.3"))

	ictx := mocks.NewMockInvocationContext(ctrl)
	ictx.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	ictx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	ictx.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(mockConfig)).AnyTimes()
	ictx.EXPECT().GetLogger().Return(mockLogger).AnyTimes()
	ictx.EXPECT().GetRuntimeInfo().Return(mockRuntimeInfo).AnyTimes()

	return ictx
}
