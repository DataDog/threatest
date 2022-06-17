package threatest

import (
	detonatorMocks "github.com/datadog/threatest/pkg/threatest/detonators/mocks"
	"github.com/datadog/threatest/pkg/threatest/matchers"
	matcherMocks "github.com/datadog/threatest/pkg/threatest/matchers/mocks"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

//TODO nuke interval for tests

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

			mockMatcher := &matcherMocks.AlertGeneratedMatcher{}
			if len(testCase.AlertExistsSequence) == 1 {
				mockMatcher.On("HasExpectedAlert", "my-uid").Return(testCase.AlertExistsSequence[0], nil)
			} else {
				for i := range testCase.AlertExistsSequence {
					mockMatcher.On("HasExpectedAlert", "my-uid").Return(testCase.AlertExistsSequence[i], nil).Once()
				}
			}
			mockMatcher.On("String").Return("sample")
			mockMatcher.On("Cleanup", "my-uid").Return(nil)

			var assertions []matchers.AlertGeneratedMatcher
			assertions = []matchers.AlertGeneratedMatcher{}
			if !testCase.HasNoAssertion {
				assertions = []matchers.AlertGeneratedMatcher{mockMatcher}
			}

			runner := TestRunner{
				Scenarios: []*Scenario{
					{
						Name:       "test-scenario",
						Detonator:  mockDetonator,
						Assertions: assertions,
						Timeout:    5 * time.Second,
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
				mockMatcher.AssertCalled(t, "Cleanup", "my-uid")
			}

		})
	}

}
