package datadog

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/aws/smithy-go/ptr"
	"github.com/datadog/threatest/pkg/threatest/matchers/datadog/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Utility function to returns a sample Datadog signal
func sampleSignal(id int) *datadogV2.SecurityMonitoringSignal {
	signal := datadogV2.NewSecurityMonitoringSignal()
	signal.Id = ptr.String(strconv.Itoa(id))
	signal.Attributes = &datadogV2.SecurityMonitoringSignalAttributes{Custom: map[string]interface{}{}}
	signal.Attributes.Custom["title"] = "Sample signal " + strconv.Itoa(id)
	return signal
}

// Utility function that generates a "universe of signals" that match either nothing, either the rule name + severity, either the
// execution UID, either both
func generateSignals(numSignalsMatchingNothing int, numSignalsMatchingRuleAndSeverity int, numSignalsMatchingUUID int, numSignalsMatchingBoth int, detonationUid string) ([]datadogV2.SecurityMonitoringSignal, []datadogV2.SecurityMonitoringSignal, []datadogV2.SecurityMonitoringSignal, []datadogV2.SecurityMonitoringSignal) {
	signalsMatchingDetonationUid := make([]datadogV2.SecurityMonitoringSignal, 0)
	signalsMatchingRuleAndSeverity := make([]datadogV2.SecurityMonitoringSignal, 0)
	signalsMatchingNothing := make([]datadogV2.SecurityMonitoringSignal, 0)
	signalsMatchingBoth := make([]datadogV2.SecurityMonitoringSignal, 0)

	for i := 0; i < numSignalsMatchingNothing; i++ {
		signalsMatchingNothing = append(signalsMatchingNothing, *sampleSignal(i))
	}
	for i := 0; i < numSignalsMatchingUUID; i++ {
		signal := *sampleSignal(i + numSignalsMatchingNothing)
		signal.Attributes.Custom["foobar"] = detonationUid
		signalsMatchingDetonationUid = append(signalsMatchingDetonationUid, signal)
	}
	for i := 0; i < numSignalsMatchingRuleAndSeverity; i++ {
		signalsMatchingRuleAndSeverity = append(signalsMatchingRuleAndSeverity, *sampleSignal(i + numSignalsMatchingNothing + numSignalsMatchingUUID))
	}
	for i := 0; i < numSignalsMatchingBoth; i++ {
		signal := *sampleSignal(i + numSignalsMatchingNothing + numSignalsMatchingUUID + numSignalsMatchingRuleAndSeverity)
		signal.Attributes.Custom["foobar"] = detonationUid
		signalsMatchingBoth = append(signalsMatchingBoth, signal)
	}

	return signalsMatchingNothing, signalsMatchingRuleAndSeverity, signalsMatchingDetonationUid, signalsMatchingBoth
}

func union(signals ...[]datadogV2.SecurityMonitoringSignal) []datadogV2.SecurityMonitoringSignal {
	result := make([]datadogV2.SecurityMonitoringSignal, 0)
	for _, signalSet := range signals {
		result = append(result, signalSet...)
	}
	return result
}
func TestDatadog(t *testing.T) {
	detonationUid := "my-detonation-uuid"
	tests := []struct {
		Name                                  string
		NumSignalsMatchingNothing             int // all signals matching neither rule/severity nor UID
		NumSignalsMatchingOnlyRuleAndSeverity int // signals matching only the rule name
		NumSignalsMatchingOnlyUUID            int // signals matching only the detonation UUID
		NumSignalsMatchingBoth                int // signals matching both
		ExpectMatch                           bool
	}{
		{
			Name:                                  "No matching at all",
			NumSignalsMatchingNothing:             0,
			NumSignalsMatchingOnlyRuleAndSeverity: 0,
			NumSignalsMatchingOnlyUUID:            0,
			NumSignalsMatchingBoth:                0,
			ExpectMatch:                           false,
		},
		{
			Name:                                  "No matching signal matching anything",
			NumSignalsMatchingNothing:             1,
			NumSignalsMatchingOnlyRuleAndSeverity: 0,
			NumSignalsMatchingOnlyUUID:            0,
			NumSignalsMatchingBoth:                0,
			ExpectMatch:                           false,
		},
		{
			Name:                                  "One signal matching alert name and severity, but not the detonation UID, should not be closed and not result in a match",
			NumSignalsMatchingNothing:             0,
			NumSignalsMatchingOnlyRuleAndSeverity: 1,
			NumSignalsMatchingOnlyUUID:            0,
			NumSignalsMatchingBoth:                0,
			ExpectMatch:                           false,
		},
		{
			Name:                                  "One signal matching the detonation UID, but not the alert name, should be closed without match",
			NumSignalsMatchingNothing:             0,
			NumSignalsMatchingOnlyRuleAndSeverity: 0,
			NumSignalsMatchingOnlyUUID:            1,
			NumSignalsMatchingBoth:                0,
			ExpectMatch:                           false,
		},
		{
			Name:                                  "One signal the detonation UID and the alert name should be closed with a match",
			NumSignalsMatchingNothing:             0,
			NumSignalsMatchingOnlyRuleAndSeverity: 0,
			NumSignalsMatchingOnlyUUID:            0,
			NumSignalsMatchingBoth:                1,
			ExpectMatch:                           true,
		},
		{
			Name:                                  "One signal matching everything, one signal matching rule name but not UID",
			NumSignalsMatchingNothing:             0,
			NumSignalsMatchingOnlyRuleAndSeverity: 0,
			NumSignalsMatchingOnlyUUID:            1,
			NumSignalsMatchingBoth:                1,
			ExpectMatch:                           true,
		},
		{
			Name:                                  "One signal matching everything, one signal matching rule name but not UID, one signal matching only UID",
			NumSignalsMatchingNothing:             0,
			NumSignalsMatchingOnlyRuleAndSeverity: 1,
			NumSignalsMatchingOnlyUUID:            1,
			NumSignalsMatchingBoth:                1,
			ExpectMatch:                           true,
		},
		{
			Name:                                  "One of each",
			NumSignalsMatchingNothing:             1,
			NumSignalsMatchingOnlyRuleAndSeverity: 1,
			NumSignalsMatchingOnlyUUID:            1,
			NumSignalsMatchingBoth:                1,
			ExpectMatch:                           true,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			mockDatadog := &mocks.DatadogSecuritySignalsAPI{}
			detonationUid = "my-uid"
			signalsMatchingNothing, signalsMatchingOnlyRuleAndSeverity, signalsMatchingOnlyDetonationUid, signalsMatchingBoth := generateSignals(test.NumSignalsMatchingNothing, test.NumSignalsMatchingOnlyRuleAndSeverity, test.NumSignalsMatchingOnlyUUID, test.NumSignalsMatchingBoth, detonationUid)
			allOpenSignals := union(signalsMatchingNothing, signalsMatchingOnlyRuleAndSeverity, signalsMatchingOnlyDetonationUid, signalsMatchingBoth)
			alertFilter := &DatadogAlertFilter{RuleName: "my-rule-name", Severity: "medium"}
			expectedQuery := fmt.Sprintf(
				QueryOpenSignalsByAlertNameAndSeverity,
				alertFilter.RuleName,
				fmt.Sprintf(QuerySeverity, alertFilter.Severity)+" ",
			)

			mockDatadog.On("SearchSignals", QueryAllOpenSignals).Return(allOpenSignals, nil)
			mockDatadog.On("SearchSignals", expectedQuery).Return(union(signalsMatchingOnlyRuleAndSeverity, signalsMatchingBoth), nil)
			mockDatadog.On("CloseSignal", mock.AnythingOfType("string")).Return(nil)

			matcher := DatadogAlertGeneratedAssertion{
				SignalsAPI:  mockDatadog,
				AlertFilter: alertFilter,
			}

			matches, err := matcher.HasExpectedAlert(detonationUid)
			require.Nil(t, err)

			// Check expected match
			if test.ExpectMatch {
				assert.True(t, matches, "matcher should match the signal")
			} else {
				assert.False(t, matches, "matcher should not match the signal")
			}

			// Check if the Datadog API is queried with the expected query
			mockDatadog.AssertCalled(t, "SearchSignals", expectedQuery) // first query to find the relevant signals

			// CLEANUP
			//TODO split test?
			err = matcher.Cleanup(detonationUid)
			require.Nil(t, err)

			// Every signal matching the UID (independently of whether it matches the alert name) should be closed
			for i := 0; i < test.NumSignalsMatchingOnlyUUID; i++ {
				mockDatadog.AssertCalled(t, "CloseSignal", *signalsMatchingOnlyDetonationUid[i].Id)
			}
			for i := 0; i < test.NumSignalsMatchingBoth; i++ {
				mockDatadog.AssertCalled(t, "CloseSignal", *signalsMatchingBoth[i].Id)
			}
		})
	}

}
