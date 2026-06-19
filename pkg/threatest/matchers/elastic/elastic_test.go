package elastic_test

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/datadog/threatest/pkg/threatest/matchers/elastic"
	"github.com/datadog/threatest/pkg/threatest/matchers/elastic/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const testRuleName = "my-rule-name"
const detonationUID = "my-detonation-uuid"

func sampleAlert(id int) elastic.ElasticSecurityDetectionAlert {
	return elastic.ElasticSecurityDetectionAlert{
		ID:    strconv.Itoa(id),
		Index: ".alerts-security.alerts-default",
		Source: map[string]any{
			"kibana.alert.rule.name": "some-other-rule",
		},
	}
}

// alertWithUID returns an alert that references the detonation UID.
func alertWithUID(id int, uid string) elastic.ElasticSecurityDetectionAlert {
	a := sampleAlert(id)
	a.Source["correlation_id"] = uid
	return a
}

// alertWithRule returns an alert matching the test rule name and severity.
func alertWithRule(id int) elastic.ElasticSecurityDetectionAlert {
	a := sampleAlert(id)
	a.Source["kibana.alert.rule.name"] = testRuleName
	a.Source["kibana.alert.severity"] = "medium"
	return a
}

// alertWithBoth returns an alert matching the rule name, severity, and UID.
func alertWithBoth(id int, uid string) elastic.ElasticSecurityDetectionAlert {
	a := alertWithRule(id)
	a.Source["correlation_id"] = uid
	return a
}

func newMatcher(api elastic.ElasticSecurityDetectionAlertsAPI) elastic.ElasticSecurityAlertGeneratedAssertion {
	return elastic.ElasticSecurityAlertGeneratedAssertion{
		AlertsAPI:   api,
		AlertFilter: &elastic.ElasticSecurityAlertFilter{RuleName: testRuleName, Severity: "medium"},
	}
}

func TestHasExpectedAlert(t *testing.T) {
	containsRuleName := func(query string) bool { return strings.Contains(query, testRuleName) }

	// The rule-scoped Elastic query already filters by rule name, so the API
	// returns only alerts matching the rule. HasExpectedAlert then additionally
	// checks for the detonation UID in the alert source.
	tests := []struct {
		name        string
		alerts      []elastic.ElasticSecurityDetectionAlert
		expectMatch bool
	}{
		{
			name:        "no alerts",
			alerts:      nil,
			expectMatch: false,
		},
		{
			name:        "alert matches rule but not UID",
			alerts:      []elastic.ElasticSecurityDetectionAlert{alertWithRule(0)},
			expectMatch: false,
		},
		{
			name:        "alert matches both rule and UID",
			alerts:      []elastic.ElasticSecurityDetectionAlert{alertWithBoth(0, detonationUID)},
			expectMatch: true,
		},
		{
			name: "multiple alerts, only one matches UID",
			alerts: []elastic.ElasticSecurityDetectionAlert{
				alertWithRule(0),
				alertWithBoth(1, detonationUID),
			},
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAPI := mocks.NewElasticSecurityDetectionAlertsAPI(t)
			mockAPI.On("SearchAlerts", mock.Anything, mock.MatchedBy(containsRuleName)).Return(tt.alerts, nil)

			matcher := newMatcher(mockAPI)
			matches, err := matcher.HasExpectedAlert(context.Background(), detonationUID)
			require.NoError(t, err)
			assert.Equal(t, tt.expectMatch, matches)
		})
	}
}

func TestCleanup(t *testing.T) {
	isAllOpenQuery := func(query string) bool { return !strings.Contains(query, testRuleName) }

	matchingAlert := alertWithBoth(0, detonationUID)
	uidOnlyAlert := alertWithUID(1, detonationUID)
	ruleOnlyAlert := alertWithRule(2)
	unrelatedAlert := sampleAlert(3)

	allAlerts := []elastic.ElasticSecurityDetectionAlert{matchingAlert, uidOnlyAlert, ruleOnlyAlert, unrelatedAlert}

	mockAPI := mocks.NewElasticSecurityDetectionAlertsAPI(t)
	mockAPI.On("SearchAlerts", mock.Anything, mock.MatchedBy(isAllOpenQuery)).Return(allAlerts, nil)
	mockAPI.On("CloseAlert", mock.Anything, matchingAlert.ID).Return(nil)
	mockAPI.On("CloseAlert", mock.Anything, uidOnlyAlert.ID).Return(nil)

	matcher := newMatcher(mockAPI)
	require.NoError(t, matcher.Cleanup(context.Background(), detonationUID))

	mockAPI.AssertCalled(t, "CloseAlert", mock.Anything, matchingAlert.ID)
	mockAPI.AssertCalled(t, "CloseAlert", mock.Anything, uidOnlyAlert.ID)
	mockAPI.AssertNotCalled(t, "CloseAlert", mock.Anything, ruleOnlyAlert.ID)
	mockAPI.AssertNotCalled(t, "CloseAlert", mock.Anything, unrelatedAlert.ID)
}
