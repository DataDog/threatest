package threatest

import (
	"errors"
	"testing"
	"time"

	detonatorMocks "github.com/datadog/threatest/pkg/threatest/detonators/mocks"
	"github.com/datadog/threatest/pkg/threatest/matchers"
	matcherMocks "github.com/datadog/threatest/pkg/threatest/matchers/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRunnerWorks(t *testing.T) {
	testCases := []struct {
		Name                string
		AlertExistsSequence []bool
		HasNoAssertion      bool
		ExpectError         bool
	}{
		{Name: "Alert exists from the beginning", AlertExistsSequence: []bool{true}},
		{Name: "Alert doesn't exist then exists", AlertExistsSequence: []bool{false, true}},
		{Name: "Alert never exists", AlertExistsSequence: []bool{false}, ExpectError: true},
		{Name: "No assertion", HasNoAssertion: true},
	}

	for i := range testCases {
		testCase := testCases[i]

		t.Run(testCase.Name, func(t *testing.T) {
			t.Parallel()
			mockDetonator := &detonatorMocks.Detonator{}
			mockDetonator.On("Detonate").Return("my-uid", nil)

			mockMatcher := &matcherMocks.TelemetryMatcher{}
			if len(testCase.AlertExistsSequence) == 1 {
				mockMatcher.On("HasExpected", mock.Anything, "my-uid").Return(testCase.AlertExistsSequence[0], nil)
			} else {
				for i := range testCase.AlertExistsSequence {
					mockMatcher.On("HasExpected", mock.Anything, "my-uid").Return(testCase.AlertExistsSequence[i], nil).Once()
				}
			}
			mockMatcher.On("String").Return("sample")
			mockMatcher.On("Cleanup", mock.Anything, "my-uid").Return(nil)

			var assertions []TelemetryAssertion
			if !testCase.HasNoAssertion {
				assertions = []TelemetryAssertion{{Matcher: mockMatcher}}
			}

			runner := TestRunner{
				Scenarios: []*Scenario{
					{
						Name:                "test-scenario",
						Detonator:           mockDetonator,
						TelemetryAssertions: assertions,
						Timeout:             5 * time.Second,
					},
				},
				Interval: 0,
			}
			err := runner.Run()
			if testCase.ExpectError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
			mockDetonator.AssertNumberOfCalls(t, "Detonate", 1)

			if !testCase.HasNoAssertion {
				mockMatcher.AssertCalled(t, "Cleanup", mock.Anything, "my-uid")
			}

		})
	}

}

func TestRunnerErrorHandling(t *testing.T) {

	mockDetonator := &detonatorMocks.Detonator{}
	mockDetonator.On("Detonate").Return("my-uid", nil)

	mockFailingDetonator := &detonatorMocks.Detonator{}
	mockFailingDetonator.On("Detonate").Return("", errors.New("foo"))

	mockMatcher := &matcherMocks.TelemetryMatcher{}
	mockMatcher.On("String").Return("sample")
	mockMatcher.On("Cleanup", mock.Anything, "my-uid").Return(nil)
	mockMatcher.On("HasExpected", mock.Anything, "my-uid").Return(true, nil)

	runner := TestRunner{
		Scenarios: []*Scenario{
			{
				Name:                "test-scenario1",
				Detonator:           mockDetonator,
				TelemetryAssertions: []TelemetryAssertion{{Matcher: mockMatcher}},
				Timeout:             5 * time.Second,
			},
			{
				Name:                "test-scenario2-error",
				Detonator:           mockFailingDetonator,
				TelemetryAssertions: []TelemetryAssertion{{Matcher: mockMatcher}},
				Timeout:             5 * time.Second,
			},
			{
				Name:                "test-scenario3",
				Detonator:           mockDetonator,
				TelemetryAssertions: []TelemetryAssertion{{Matcher: mockMatcher}},
				Timeout:             5 * time.Second,
			},
		},
		Interval: 0,
	}
	err := runner.Run()
	assert.Error(t, err, "the runner should return an error when a scenario returns an error")

	mockDetonator.AssertNumberOfCalls(t, "Detonate", 2)
	mockFailingDetonator.AssertNumberOfCalls(t, "Detonate", 1)
}

func TestDiscoverCollectsAndNeverFails(t *testing.T) {
	mockDetonator := &detonatorMocks.Detonator{}
	mockDetonator.On("Detonate").Return("my-uid", nil)

	mockMatcher := &matcherMocks.TelemetryMatcher{}
	mockMatcher.On("Related", mock.Anything, "my-uid").Return(map[string]matchers.ThreatestEvent{
		"obj-1": {EventName: "log", Attributes: map[string]any{"message": "hello"}},
	}, nil)
	mockMatcher.On("String").Return("datadog logs")

	runner := TestRunner{
		Scenarios: []*Scenario{
			{
				Name:      "discover",
				Detonator: mockDetonator,
				TelemetryAssertions: []TelemetryAssertion{
					{Matcher: mockMatcher, Discover: true},
				},
				Timeout: 5 * time.Second,
			},
		},
		Interval: 0,
	}

	err := runner.Run()
	assert.Nil(t, err, "discover entries should never cause failure")
	assert.Len(t, runner.Scenarios[0].TelemetryAssertions[0].Discovered, 1)
	assert.Equal(t, "hello", runner.Scenarios[0].TelemetryAssertions[0].Discovered["obj-1"].Attributes["message"])
}

func TestDiscoverSkipsCleanup(t *testing.T) {
	mockDetonator := &detonatorMocks.Detonator{}
	mockDetonator.On("Detonate").Return("my-uid", nil)

	mockMatcher := &matcherMocks.TelemetryMatcher{}
	mockMatcher.On("Related", mock.Anything, "my-uid").Return(map[string]matchers.ThreatestEvent{}, nil)
	mockMatcher.On("String").Return("datadog logs")
	mockMatcher.On("Cleanup", mock.Anything, "my-uid").Return(nil)

	runner := TestRunner{
		Scenarios: []*Scenario{
			{
				Name:      "discover-no-cleanup",
				Detonator: mockDetonator,
				TelemetryAssertions: []TelemetryAssertion{
					{Matcher: mockMatcher, Discover: true},
				},
				Timeout: 100 * time.Millisecond,
			},
		},
		Interval: 10 * time.Millisecond,
	}

	err := runner.Run()
	assert.Nil(t, err)
	mockMatcher.AssertNumberOfCalls(t, "Cleanup", 0)
}

func TestDiscoverWithCustomQuery(t *testing.T) {
	mockDetonator := &detonatorMocks.Detonator{}
	mockDetonator.On("Detonate").Return("my-uid", nil)

	mockMatcher := &matcherMocks.TelemetryMatcher{}
	mockMatcher.On("Search", mock.Anything, "service:aws my-uid").Return(map[string]matchers.ThreatestEvent{
		"obj-1": {EventName: "log", Attributes: map[string]any{"message": "cloudtrail event"}},
	}, nil)
	mockMatcher.On("String").Return("datadog logs")

	runner := TestRunner{
		Scenarios: []*Scenario{
			{
				Name:      "discover-query",
				Detonator: mockDetonator,
				TelemetryAssertions: []TelemetryAssertion{
					{Matcher: mockMatcher, Discover: true, Query: "service:aws <% .CorrelationID %>"},
				},
				Timeout: 5 * time.Second,
			},
		},
		Interval: 0,
	}

	err := runner.Run()
	assert.Nil(t, err)
	assert.Len(t, runner.Scenarios[0].TelemetryAssertions[0].Discovered, 1)
	mockMatcher.AssertCalled(t, "Search", mock.Anything, "service:aws my-uid")
}

func TestDiscoverDoesNotStarveLaterAssertion(t *testing.T) {
	mockDetonator := &detonatorMocks.Detonator{}
	mockDetonator.On("Detonate").Return("my-uid", nil)

	mockAlertMatcher := &matcherMocks.TelemetryMatcher{}
	mockAlertMatcher.On("HasExpected", mock.Anything, "my-uid").Return(true, nil)
	mockAlertMatcher.On("String").Return("signal")
	mockAlertMatcher.On("Cleanup", mock.Anything, "my-uid").Return(nil)

	mockTelemetryMatcher := &matcherMocks.TelemetryMatcher{}
	mockTelemetryMatcher.On("Related", mock.Anything, "my-uid").Return(map[string]matchers.ThreatestEvent{}, nil)
	mockTelemetryMatcher.On("String").Return("datadog logs")

	runner := TestRunner{
		Scenarios: []*Scenario{
			{
				Name:      "discover-before-assert",
				Detonator: mockDetonator,
				TelemetryAssertions: []TelemetryAssertion{
					{Matcher: mockTelemetryMatcher, Discover: true},
					{Matcher: mockAlertMatcher},
				},
				Timeout: 5 * time.Second,
			},
		},
		Interval: 0,
	}

	err := runner.Run()
	assert.Nil(t, err, "assert after discover should still get a polling window")
	mockAlertMatcher.AssertCalled(t, "HasExpected", mock.Anything, "my-uid")
}
