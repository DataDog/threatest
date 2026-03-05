package datadog

import (
	"fmt"
	"testing"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/aws/smithy-go/ptr"
	"github.com/datadog/threatest/pkg/threatest/matchers/datadog/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func uidQuery(uid string) string {
	return fmt.Sprintf(QueryOpenSignalsByExecutionUID, uid)
}

func signalWithUID(id string, uid string, ruleName string, severity string) datadogV2.SecurityMonitoringSignal {
	signal := datadogV2.NewSecurityMonitoringSignal()
	signal.Id = ptr.String(id)
	now := time.Now()
	signal.Attributes = &datadogV2.SecurityMonitoringSignalAttributes{
		Custom: map[string]interface{}{
			"detonation": uid,
			"workflow": map[string]interface{}{
				"rule": map[string]interface{}{
					"name": ruleName,
				},
			},
		},
		Message:   ptr.String("test message"),
		Timestamp: &now,
		Tags:      []string{"status:" + severity, "env:test"},
	}
	return *signal
}

func TestDiscoverSignals_MatchesUID(t *testing.T) {
	mockAPI := &mocks.DatadogSecuritySignalsAPI{}
	uid := "test-uid-123"

	sig1 := signalWithUID("sig-1", uid, "Rule A", "high")
	sig2 := signalWithUID("sig-2", uid, "Rule B", "low")

	mockAPI.On("SearchSignals", uidQuery(uid)).Return([]datadogV2.SecurityMonitoringSignal{sig1, sig2}, nil)

	signals, err := DiscoverSignals(mockAPI, uid)
	require.NoError(t, err)
	assert.Len(t, signals, 2)
	assert.Equal(t, "sig-1", signals[0].SignalID)
	assert.Equal(t, "Rule A", signals[0].RuleName)
	assert.Equal(t, "high", signals[0].Severity)
	assert.Equal(t, "test message", signals[0].Message)
	assert.Equal(t, []string{"status:high", "env:test"}, signals[0].Tags)
}

func TestDiscoverSignals_NilAttributes(t *testing.T) {
	mockAPI := &mocks.DatadogSecuritySignalsAPI{}
	uid := "test-uid"

	signal := datadogV2.NewSecurityMonitoringSignal()
	signal.Id = ptr.String("sig-nil")
	signal.Attributes = nil

	mockAPI.On("SearchSignals", uidQuery(uid)).Return([]datadogV2.SecurityMonitoringSignal{*signal}, nil)

	signals, err := DiscoverSignals(mockAPI, uid)
	require.NoError(t, err)
	assert.Empty(t, signals)
}

func TestDiscoverSignals_NoMatches(t *testing.T) {
	mockAPI := &mocks.DatadogSecuritySignalsAPI{}
	uid := "uid"
	mockAPI.On("SearchSignals", uidQuery(uid)).Return([]datadogV2.SecurityMonitoringSignal{}, nil)

	signals, err := DiscoverSignals(mockAPI, uid)
	require.NoError(t, err)
	assert.Empty(t, signals)
}

func TestDiscoverSignals_QueryContainsUID(t *testing.T) {
	mockAPI := &mocks.DatadogSecuritySignalsAPI{}
	uid := "stratus-red-team_cb44b086-ca36-4b28-8faa-df408165d9a9"
	expectedQuery := "@workflow.triage.state:open " + uid

	mockAPI.On("SearchSignals", expectedQuery).Return([]datadogV2.SecurityMonitoringSignal{}, nil)

	_, err := DiscoverSignals(mockAPI, uid)
	require.NoError(t, err)
	mockAPI.AssertCalled(t, "SearchSignals", expectedQuery)
}

func TestExtractRuleName_MissingFields(t *testing.T) {
	assert.Equal(t, "", extractRuleName(nil))
	assert.Equal(t, "", extractRuleName(map[string]interface{}{}))
	assert.Equal(t, "", extractRuleName(map[string]interface{}{"workflow": "not-a-map"}))
	assert.Equal(t, "", extractRuleName(map[string]interface{}{
		"workflow": map[string]interface{}{"rule": "not-a-map"},
	}))
	assert.Equal(t, "MyRule", extractRuleName(map[string]interface{}{
		"workflow": map[string]interface{}{
			"rule": map[string]interface{}{
				"name": "MyRule",
			},
		},
	}))
}

func TestExtractSeverity(t *testing.T) {
	assert.Equal(t, "", extractSeverity(nil))
	assert.Equal(t, "", extractSeverity([]string{"env:prod"}))
	assert.Equal(t, "medium", extractSeverity([]string{"env:prod", "status:medium"}))
}

func TestDiscoverSignals_NilMessageAndTimestamp(t *testing.T) {
	mockAPI := &mocks.DatadogSecuritySignalsAPI{}
	uid := "uid-nil-fields"

	signal := datadogV2.NewSecurityMonitoringSignal()
	signal.Id = ptr.String("sig-partial")
	signal.Attributes = &datadogV2.SecurityMonitoringSignalAttributes{
		Custom: map[string]interface{}{
			"data": uid,
		},
	}

	mockAPI.On("SearchSignals", uidQuery(uid)).Return([]datadogV2.SecurityMonitoringSignal{*signal}, nil)

	signals, err := DiscoverSignals(mockAPI, uid)
	require.NoError(t, err)
	assert.Len(t, signals, 1)
	assert.Equal(t, "sig-partial", signals[0].SignalID)
	assert.Equal(t, "", signals[0].Message)
	assert.Equal(t, "", signals[0].RuleName)
	assert.True(t, signals[0].Timestamp.IsZero())
	assert.Nil(t, signals[0].Tags)
}
