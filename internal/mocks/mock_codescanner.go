// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/snyk/code-client-go (interfaces: CodeScanner)
//
// Generated by this command:
//
//	mockgen -package=mocks -destination=../../mocks/mock_codescanner.go github.com/snyk/code-client-go CodeScanner
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	bundle "github.com/snyk/code-client-go/bundle"
	sarif "github.com/snyk/code-client-go/sarif"
	scan "github.com/snyk/code-client-go/scan"
	gomock "go.uber.org/mock/gomock"
)

// MockCodeScanner is a mock of CodeScanner interface.
type MockCodeScanner struct {
	ctrl     *gomock.Controller
	recorder *MockCodeScannerMockRecorder
	isgomock struct{}
}

// MockCodeScannerMockRecorder is the mock recorder for MockCodeScanner.
type MockCodeScannerMockRecorder struct {
	mock *MockCodeScanner
}

// NewMockCodeScanner creates a new mock instance.
func NewMockCodeScanner(ctrl *gomock.Controller) *MockCodeScanner {
	mock := &MockCodeScanner{ctrl: ctrl}
	mock.recorder = &MockCodeScannerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockCodeScanner) EXPECT() *MockCodeScannerMockRecorder {
	return m.recorder
}

// Upload mocks base method.
func (m *MockCodeScanner) Upload(ctx context.Context, requestId string, target scan.Target, files <-chan string, changedFiles map[string]bool) (bundle.Bundle, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Upload", ctx, requestId, target, files, changedFiles)
	ret0, _ := ret[0].(bundle.Bundle)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Upload indicates an expected call of Upload.
func (mr *MockCodeScannerMockRecorder) Upload(ctx, requestId, target, files, changedFiles any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Upload", reflect.TypeOf((*MockCodeScanner)(nil).Upload), ctx, requestId, target, files, changedFiles)
}

// UploadAndAnalyze mocks base method.
func (m *MockCodeScanner) UploadAndAnalyze(ctx context.Context, requestId string, target scan.Target, files <-chan string, changedFiles map[string]bool) (*sarif.SarifResponse, string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UploadAndAnalyze", ctx, requestId, target, files, changedFiles)
	ret0, _ := ret[0].(*sarif.SarifResponse)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// UploadAndAnalyze indicates an expected call of UploadAndAnalyze.
func (mr *MockCodeScannerMockRecorder) UploadAndAnalyze(ctx, requestId, target, files, changedFiles any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UploadAndAnalyze", reflect.TypeOf((*MockCodeScanner)(nil).UploadAndAnalyze), ctx, requestId, target, files, changedFiles)
}
