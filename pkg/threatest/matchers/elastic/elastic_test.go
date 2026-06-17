package elastic

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const testRuleName = "my-rule-name"

// fakeAlertsAPI is an in-package testify mock for ElasticSecurityDetectionAlertsAPI.
// We can't reuse the generated ./mocks package here because it imports this
// package, which would create an import cycle in the white-box test.
type fakeAlertsAPI struct {
	mock.Mock
}

func (f *fakeAlertsAPI) SearchAlerts(ctx context.Context, query string) ([]ElasticSecurityDetectionAlert, error) {
	args := f.Called(ctx, query)
	return args.Get(0).([]ElasticSecurityDetectionAlert), args.Error(1)
}

func (f *fakeAlertsAPI) CloseAlert(ctx context.Context, id string) error {
	args := f.Called(ctx, id)
	return args.Error(0)
}

// sampleAlert returns a sample Elastic Security alert that matches neither the
// rule name nor the detonation UID.
func sampleAlert(id int) ElasticSecurityDetectionAlert {
	return ElasticSecurityDetectionAlert{
		ID:    strconv.Itoa(id),
		Index: ".alerts-security.alerts-default",
		Source: map[string]interface{}{
			"kibana.alert.rule.name": "some-other-rule",
		},
	}
}

// generateAlerts builds a universe of alerts split into four buckets, mirroring
// the Datadog matcher tests: alerts matching nothing, alerts matching only the
// rule name + severity, alerts matching only the detonation UID, and alerts
// matching both.
func generateAlerts(numNothing, numRuleAndSeverity, numUUID, numBoth int, detonationUid string) (nothing, ruleAndSeverity, uuidOnly, both []ElasticSecurityDetectionAlert) {
	offset := 0
	for i := 0; i < numNothing; i++ {
		nothing = append(nothing, sampleAlert(offset))
		offset++
	}
	for i := 0; i < numUUID; i++ {
		alert := sampleAlert(offset)
		alert.Source["correlation_id"] = detonationUid
		uuidOnly = append(uuidOnly, alert)
		offset++
	}
	for i := 0; i < numRuleAndSeverity; i++ {
		alert := sampleAlert(offset)
		alert.Source["kibana.alert.rule.name"] = testRuleName
		alert.Source["kibana.alert.severity"] = "medium"
		ruleAndSeverity = append(ruleAndSeverity, alert)
		offset++
	}
	for i := 0; i < numBoth; i++ {
		alert := sampleAlert(offset)
		alert.Source["kibana.alert.rule.name"] = testRuleName
		alert.Source["kibana.alert.severity"] = "medium"
		alert.Source["correlation_id"] = detonationUid
		both = append(both, alert)
		offset++
	}
	return
}

func union(sets ...[]ElasticSecurityDetectionAlert) []ElasticSecurityDetectionAlert {
	result := make([]ElasticSecurityDetectionAlert, 0)
	for _, set := range sets {
		result = append(result, set...)
	}
	return result
}

func TestElastic(t *testing.T) {
	ctx := context.Background()
	detonationUid := "my-detonation-uuid"
	tests := []struct {
		Name                                 string
		NumAlertsMatchingNothing             int
		NumAlertsMatchingOnlyRuleAndSeverity int
		NumAlertsMatchingOnlyUUID            int
		NumAlertsMatchingBoth                int
		ExpectMatch                          bool
	}{
		{Name: "No matching at all", ExpectMatch: false},
		{Name: "One alert matching nothing", NumAlertsMatchingNothing: 1, ExpectMatch: false},
		{Name: "One alert matching rule and severity but not the detonation UID", NumAlertsMatchingOnlyRuleAndSeverity: 1, ExpectMatch: false},
		{Name: "One alert matching the detonation UID but not the rule name", NumAlertsMatchingOnlyUUID: 1, ExpectMatch: false},
		{Name: "One alert matching the detonation UID and the rule name", NumAlertsMatchingBoth: 1, ExpectMatch: true},
		{Name: "One alert matching everything, one matching UID only", NumAlertsMatchingOnlyUUID: 1, NumAlertsMatchingBoth: 1, ExpectMatch: true},
		{Name: "One of each", NumAlertsMatchingNothing: 1, NumAlertsMatchingOnlyRuleAndSeverity: 1, NumAlertsMatchingOnlyUUID: 1, NumAlertsMatchingBoth: 1, ExpectMatch: true},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			mockElastic := &fakeAlertsAPI{}
			nothing, ruleAndSeverity, uuidOnly, both := generateAlerts(
				test.NumAlertsMatchingNothing,
				test.NumAlertsMatchingOnlyRuleAndSeverity,
				test.NumAlertsMatchingOnlyUUID,
				test.NumAlertsMatchingBoth,
				detonationUid,
			)
			allOpenAlerts := union(nothing, ruleAndSeverity, uuidOnly, both)

			// The rule-scoped query contains the rule name; the all-open query
			// (used by Cleanup) does not. We match on that to stay robust against
			// the timestamp embedded in each generated query.
			containsRuleName := func(query string) bool { return strings.Contains(query, testRuleName) }
			isAllOpenQuery := func(query string) bool { return !strings.Contains(query, testRuleName) }

			mockElastic.On("SearchAlerts", mock.Anything, mock.MatchedBy(containsRuleName)).Return(union(ruleAndSeverity, both), nil)
			mockElastic.On("SearchAlerts", mock.Anything, mock.MatchedBy(isAllOpenQuery)).Return(allOpenAlerts, nil)
			mockElastic.On("CloseAlert", mock.Anything, mock.AnythingOfType("string")).Return(nil)

			matcher := ElasticSecurityAlertGeneratedAssertion{
				AlertsAPI:   mockElastic,
				AlertFilter: &ElasticSecurityAlertFilter{RuleName: testRuleName, Severity: "medium"},
			}

			matches, err := matcher.HasExpectedAlert(ctx, detonationUid)
			require.Nil(t, err)
			if test.ExpectMatch {
				assert.True(t, matches, "matcher should match the alert")
			} else {
				assert.False(t, matches, "matcher should not match the alert")
			}

			// Verify the rule-scoped query was used to look for the expected alert.
			mockElastic.AssertCalled(t, "SearchAlerts", mock.Anything, mock.MatchedBy(containsRuleName))

			// Cleanup: every alert referencing the detonation UID should be closed,
			// regardless of whether it matched the rule name.
			err = matcher.Cleanup(ctx, detonationUid)
			require.Nil(t, err)

			for _, alert := range uuidOnly {
				mockElastic.AssertCalled(t, "CloseAlert", mock.Anything, alert.ID)
			}
			for _, alert := range both {
				mockElastic.AssertCalled(t, "CloseAlert", mock.Anything, alert.ID)
			}
			// Alerts not referencing the UID must never be closed.
			for _, alert := range append(nothing, ruleAndSeverity...) {
				mockElastic.AssertNotCalled(t, "CloseAlert", mock.Anything, alert.ID)
			}
		})
	}
}

func TestAlertMatchesExecution(t *testing.T) {
	uid := "test-detonation-uid"
	matcher := &ElasticSecurityAlertGeneratedAssertion{}

	t.Run("matches when UID is present in the alert source", func(t *testing.T) {
		alert := ElasticSecurityDetectionAlert{Source: map[string]interface{}{"correlation_id": uid}}
		assert.True(t, matcher.alertMatchesExecution(alert, uid))
	})

	t.Run("matches when UID is nested in the alert source", func(t *testing.T) {
		alert := ElasticSecurityDetectionAlert{Source: map[string]interface{}{
			"process": map[string]interface{}{"command_line": "curl https://example.com/" + uid},
		}}
		assert.True(t, matcher.alertMatchesExecution(alert, uid))
	})

	t.Run("does not match when UID is absent", func(t *testing.T) {
		alert := ElasticSecurityDetectionAlert{Source: map[string]interface{}{"correlation_id": "other-uid"}}
		assert.False(t, matcher.alertMatchesExecution(alert, uid))
	})
}
