package splunk

import (
	"github.com/datadog/threatest/pkg/threatest/matchers/splunk/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"strconv"
	"testing"
)

type SplunkTestNotable []map[string]interface{}

// Utility function to returns a sample notable event
func sampleNotableEvent(id int) map[string]interface{} {
	idStr := strconv.Itoa(id)
	return map[string]interface{}{
		"_id":         idStr,
		"event_id":    idStr,
		"search_name": "test-rule",
		"severity":    "critical",
		"description": "Sample notable event",
	}
}

// Utility function that generates a "universe of notable events" that match either nothing, either the rule name + severity, either the
// execution UID, either both
func generateNotableEvents(numMatchingNothing, numMatchingRuleOnly, numMatchingUUIDOnly, numMatchingBoth int, detonationUid string) (notablesMatchingNothing, notablesMatchingRuleOnly, notablesMatchingUUIDOnly, notablesMatchingBoth SplunkTestNotable) {

	// Notables matching nothing
	for i := 0; i < numMatchingNothing; i++ {
		notableEvent := sampleNotableEvent(i)
		notableEvent["search_name"] = "different-rule"
		notablesMatchingNothing = append(notablesMatchingNothing, notableEvent)
	}

	// Notables matching rule only
	for i := 0; i < numMatchingRuleOnly; i++ {
		notable := sampleNotableEvent(i + numMatchingNothing)
		notablesMatchingRuleOnly = append(notablesMatchingRuleOnly, notable)
	}

	// Notables matching UUID only
	for i := 0; i < numMatchingUUIDOnly; i++ {
		notable := sampleNotableEvent(i + numMatchingNothing + numMatchingRuleOnly)
		notable["search_name"] = "different-rule"
		notable["detectionuuid"] = detonationUid
		notablesMatchingUUIDOnly = append(notablesMatchingUUIDOnly, notable)
	}

	// Notables matching both
	for i := 0; i < numMatchingBoth; i++ {
		notable := sampleNotableEvent(i + numMatchingNothing + numMatchingRuleOnly + numMatchingUUIDOnly)
		notable["detectionuuid"] = detonationUid
		notablesMatchingBoth = append(notablesMatchingBoth, notable)
	}

	return
}

func union(notables ...[]map[string]interface{}) []map[string]interface{} {
	result := make([]map[string]interface{}, 0)
	for _, notableSet := range notables {
		result = append(result, notableSet...)
	}
	return result
}

func TestSplunk(t *testing.T) {
	detonationUid := "my-detonation-uuid"
	tests := []struct {
		Name                                   string
		NumNotablesMatchingNothing             int // all signals matching neither rule/severity nor UID
		NumNotablesMatchingOnlyRuleAndSeverity int // signals matching only the rule name
		NumNotablesMatchingOnlyUUID            int // signals matching only the detonation UUID
		NumNotablesMatchingBoth                int // signals matching both
		ExpectMatch                            bool
	}{
		{
			Name:                                   "No matching at all",
			NumNotablesMatchingNothing:             0,
			NumNotablesMatchingOnlyRuleAndSeverity: 0,
			NumNotablesMatchingOnlyUUID:            0,
			NumNotablesMatchingBoth:                0,
			ExpectMatch:                            false,
		},
		{
			Name:                                   "No matching notable event matching anything",
			NumNotablesMatchingNothing:             1,
			NumNotablesMatchingOnlyRuleAndSeverity: 0,
			NumNotablesMatchingOnlyUUID:            0,
			NumNotablesMatchingBoth:                0,
			ExpectMatch:                            false,
		},
		{
			Name:                                   "One notable event matching alert name and severity, but not the detonation UID, should not be closed and not result in a match",
			NumNotablesMatchingNothing:             0,
			NumNotablesMatchingOnlyRuleAndSeverity: 1,
			NumNotablesMatchingOnlyUUID:            0,
			NumNotablesMatchingBoth:                0,
			ExpectMatch:                            false,
		},
		{
			Name:                                   "One notable event matching the detonation UID, but not the alert name, should be closed without match",
			NumNotablesMatchingNothing:             0,
			NumNotablesMatchingOnlyRuleAndSeverity: 0,
			NumNotablesMatchingOnlyUUID:            1,
			NumNotablesMatchingBoth:                0,
			ExpectMatch:                            false,
		},
		{
			Name:                                   "One notable event the detonation UID and the alert name should be closed with a match",
			NumNotablesMatchingNothing:             0,
			NumNotablesMatchingOnlyRuleAndSeverity: 0,
			NumNotablesMatchingOnlyUUID:            0,
			NumNotablesMatchingBoth:                1,
			ExpectMatch:                            true,
		},
		{
			Name:                                   "One notable event matching everything, one notable event matching rule name but not UID",
			NumNotablesMatchingNothing:             0,
			NumNotablesMatchingOnlyRuleAndSeverity: 0,
			NumNotablesMatchingOnlyUUID:            1,
			NumNotablesMatchingBoth:                1,
			ExpectMatch:                            true,
		},
		{
			Name:                                   "One notable event matching everything, one notable event matching rule name but not UID, one notable event matching only UID",
			NumNotablesMatchingNothing:             0,
			NumNotablesMatchingOnlyRuleAndSeverity: 1,
			NumNotablesMatchingOnlyUUID:            1,
			NumNotablesMatchingBoth:                1,
			ExpectMatch:                            true,
		},
		{
			Name:                                   "One of each",
			NumNotablesMatchingNothing:             1,
			NumNotablesMatchingOnlyRuleAndSeverity: 1,
			NumNotablesMatchingOnlyUUID:            1,
			NumNotablesMatchingBoth:                1,
			ExpectMatch:                            true,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			// Setup mock
			mockAPI := new(mocks.SplunkAPI)

			// Generate test notables
			notablesMatchingNothing, notablesMatchingRuleOnly, notablesMatchingUUIDOnly, notablesMatchingBoth :=
				generateNotableEvents(
					test.NumNotablesMatchingNothing,
					test.NumNotablesMatchingOnlyRuleAndSeverity,
					test.NumNotablesMatchingOnlyUUID,
					test.NumNotablesMatchingBoth,
					detonationUid,
				)

			allNotables := union(notablesMatchingNothing, notablesMatchingRuleOnly, notablesMatchingUUIDOnly, notablesMatchingBoth)

			t.Logf("Generated notables: %+v", allNotables)

			// Setup the filter criteria
			filter := SplunkNotableFilter{
				RuleName: "test-rule",
				Severity: "critical",
			}

			// Setup mock expectations for HasExpectedAlert
			mockAPI.On("SearchNotables", mock.MatchedBy(func(f map[string]string) bool {
				return f["RuleName"] == "test-rule" && f["Severity"] == "critical" && f["DetectionUID"] == detonationUid
			})).Return(union(notablesMatchingRuleOnly, notablesMatchingBoth), nil)

			// Setup mock expectations for Cleanup
			mockAPI.On("SearchNotables", mock.MatchedBy(func(f map[string]string) bool {
				return f["DetectionUID"] == detonationUid && f["StartTime"] == "-2h"
			})).Return(allNotables, nil)

			// Setup mock expectations for CloseNotable - for any notables matching UUID
			allUUIDNotables := union(notablesMatchingUUIDOnly, notablesMatchingBoth)
			for _, notable := range allUUIDNotables {
				mockAPI.On("CloseNotable", notable["_id"].(string)).Return(nil)
			}

			// Create the assertion object
			matcher := SplunkNotableGeneratedAssertion{
				SplunkAPI:     mockAPI,
				NotableFilter: filter,
			}

			// Test HasExpectedAlert
			matches, err := matcher.HasExpectedAlert(detonationUid)
			require.NoError(t, err)

			if test.ExpectMatch {
				assert.True(t, matches, "matcher should find matching notables")
			} else {
				assert.False(t, matches, "matcher should not find matching notables")
			}

			// Test Cleanup functionality
			err = matcher.Cleanup(detonationUid)
			require.NoError(t, err)

			// Verify that all notables with UUID were closed
			for _, notable := range allUUIDNotables {
				mockAPI.AssertCalled(t, "CloseNotable", notable["_id"].(string))
			}

			// Verify notables without UUID were not closed
			for _, notable := range notablesMatchingNothing {
				mockAPI.AssertNotCalled(t, "CloseNotable", notable["_id"].(string))
			}
			for _, notable := range notablesMatchingRuleOnly {
				mockAPI.AssertNotCalled(t, "CloseNotable", notable["_id"].(string))
			}
		})
	}
}
