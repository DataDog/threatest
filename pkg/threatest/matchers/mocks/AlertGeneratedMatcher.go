// Code generated by mockery v2.13.1. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// AlertGeneratedMatcher is an autogenerated mock type for the AlertGeneratedMatcher type
type AlertGeneratedMatcher struct {
	mock.Mock
}

// Cleanup provides a mock function with given fields: uuid
func (_m *AlertGeneratedMatcher) Cleanup(uuid string) error {
	ret := _m.Called(uuid)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(uuid)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// HasExpectedAlert provides a mock function with given fields: uid
func (_m *AlertGeneratedMatcher) HasExpectedAlert(uid string) (bool, error) {
	ret := _m.Called(uid)

	var r0 bool
	if rf, ok := ret.Get(0).(func(string) bool); ok {
		r0 = rf(uid)
	} else {
		r0 = ret.Get(0).(bool)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(uid)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// String provides a mock function with given fields:
func (_m *AlertGeneratedMatcher) String() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

type mockConstructorTestingTNewAlertGeneratedMatcher interface {
	mock.TestingT
	Cleanup(func())
}

// NewAlertGeneratedMatcher creates a new instance of AlertGeneratedMatcher. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewAlertGeneratedMatcher(t mockConstructorTestingTNewAlertGeneratedMatcher) *AlertGeneratedMatcher {
	mock := &AlertGeneratedMatcher{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
