package elastic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlertMatchesExecution(t *testing.T) {
	uid := "test-detonation-uid"
	matcher := &ElasticSecurityAlertGeneratedAssertion{}

	t.Run("matches when UID is present in the alert source", func(t *testing.T) {
		alert := ElasticSecurityDetectionAlert{Source: map[string]any{"correlation_id": uid}}
		assert.True(t, matcher.alertMatchesExecution(alert, uid))
	})

	t.Run("matches when UID is nested in the alert source", func(t *testing.T) {
		alert := ElasticSecurityDetectionAlert{Source: map[string]any{
			"process": map[string]any{"command_line": "curl https://example.com/" + uid},
		}}
		assert.True(t, matcher.alertMatchesExecution(alert, uid))
	})

	t.Run("does not match when UID is absent", func(t *testing.T) {
		alert := ElasticSecurityDetectionAlert{Source: map[string]any{"correlation_id": "other-uid"}}
		assert.False(t, matcher.alertMatchesExecution(alert, uid))
	})
}

func TestBuildElasticAlertQuery(t *testing.T) {
	t.Run("includes rule name", func(t *testing.T) {
		assertion := &ElasticSecurityAlertGeneratedAssertion{
			AlertFilter: &ElasticSecurityAlertFilter{RuleName: "Test Rule"},
		}
		query := assertion.buildElasticAlertQuery()
		assert.Contains(t, query, "Test Rule")
		assert.Contains(t, query, "kibana.alert.rule.name")
		assert.NotContains(t, query, "kibana.alert.severity")
	})

	t.Run("includes severity when set", func(t *testing.T) {
		assertion := &ElasticSecurityAlertGeneratedAssertion{
			AlertFilter: &ElasticSecurityAlertFilter{RuleName: "Test Rule", Severity: "high"},
		}
		query := assertion.buildElasticAlertQuery()
		assert.Contains(t, query, "high")
		assert.Contains(t, query, "kibana.alert.severity")
	})
}

func TestBuildAllOpenAlertsQuery(t *testing.T) {
	query := buildAllOpenAlertsQuery()
	assert.NotContains(t, query, "kibana.alert.rule.name")
	assert.Contains(t, query, "kibana.alert.workflow_status")
}
