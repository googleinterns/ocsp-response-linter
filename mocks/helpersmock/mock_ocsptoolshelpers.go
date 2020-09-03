// Code generated by MockGen. DO NOT EDIT.
// Source: ocsp_tools_helpers.go

// Package helpersmock is a generated GoMock package.
package helpersmock

import (
	crypto "crypto"
	x509 "crypto/x509"
	gomock "github.com/golang/mock/gomock"
	http "net/http"
	reflect "reflect"
)

// MockHelpersInterface is a mock of HelpersInterface interface
type MockHelpersInterface struct {
	ctrl     *gomock.Controller
	recorder *MockHelpersInterfaceMockRecorder
}

// MockHelpersInterfaceMockRecorder is the mock recorder for MockHelpersInterface
type MockHelpersInterfaceMockRecorder struct {
	mock *MockHelpersInterface
}

// NewMockHelpersInterface creates a new mock instance
func NewMockHelpersInterface(ctrl *gomock.Controller) *MockHelpersInterface {
	mock := &MockHelpersInterface{ctrl: ctrl}
	mock.recorder = &MockHelpersInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockHelpersInterface) EXPECT() *MockHelpersInterfaceMockRecorder {
	return m.recorder
}

// GetCertFromIssuerURL mocks base method
func (m *MockHelpersInterface) GetCertFromIssuerURL(arg0 string) (*x509.Certificate, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetCertFromIssuerURL", arg0)
	ret0, _ := ret[0].(*x509.Certificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCertFromIssuerURL indicates an expected call of GetCertFromIssuerURL
func (mr *MockHelpersInterfaceMockRecorder) GetCertFromIssuerURL(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCertFromIssuerURL", reflect.TypeOf((*MockHelpersInterface)(nil).GetCertFromIssuerURL), arg0)
}

// CreateOCSPReq mocks base method
func (m *MockHelpersInterface) CreateOCSPReq(arg0 string, arg1, arg2 *x509.Certificate, arg3 string, arg4 crypto.Hash) (*http.Request, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateOCSPReq", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(*http.Request)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateOCSPReq indicates an expected call of CreateOCSPReq
func (mr *MockHelpersInterfaceMockRecorder) CreateOCSPReq(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateOCSPReq", reflect.TypeOf((*MockHelpersInterface)(nil).CreateOCSPReq), arg0, arg1, arg2, arg3, arg4)
}

// GetOCSPResp mocks base method
func (m *MockHelpersInterface) GetOCSPResp(arg0 *http.Request) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetOCSPResp", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetOCSPResp indicates an expected call of GetOCSPResp
func (mr *MockHelpersInterfaceMockRecorder) GetOCSPResp(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetOCSPResp", reflect.TypeOf((*MockHelpersInterface)(nil).GetOCSPResp), arg0)
}