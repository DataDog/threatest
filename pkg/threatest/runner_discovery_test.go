package threatest

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/aws/smithy-go/ptr"
	detonatorMocks "github.com/datadog/threatest/pkg/threatest/detonators/mocks"
	ddMocks "github.com/datadog/threatest/pkg/threatest/matchers/datadog/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func makeSignalWithUID(id string, uid string) datadogV2.SecurityMonitoringSignal {
	signal := datadogV2.NewSecurityMonitoringSignal()
	signal.Id = ptr.String(id)
	signal.Attributes = &datadogV2.SecurityMonitoringSignalAttributes{
		Custom: map[string]interface{}{
			"data": uid,
			"workflow": map[string]interface{}{
				"rule": map[string]interface{}{
					"name": "Rule " + id,
				},
			},
		},
		Tags: []string{"status:high"},
	}
	return *signal
}

func TestDiscoverScenario_Timeout(t *testing.T) {
	mockDetonator := &detonatorMocks.Detonator{}
	mockDetonator.On("Detonate").Return("uid-1", nil)

	mockAPI := &ddMocks.DatadogSecuritySignalsAPI{}
	mockAPI.On("SearchSignals", mock.Anything).Return([]datadogV2.SecurityMonitoringSignal{}, nil)
	mockAPI.On("CloseSignal", mock.Anything).Return(nil)

	runner := &TestRunner{
		Scenarios:  []*Scenario{{Name: "test", Detonator: mockDetonator}},
		Interval:   10 * time.Millisecond,
		SignalsAPI: mockAPI,
	}

	result := runner.DiscoverScenario(runner.Scenarios[0], DiscoveryOptions{Timeout: 50 * time.Millisecond})
	assert.NoError(t, result.Error)
	assert.Empty(t, result.Signals)
	assert.True(t, result.Duration >= 50*time.Millisecond)
}

func TestDiscoverScenario_MinSignalsEarlyExit(t *testing.T) {
	uid := "uid-min"
	mockDetonator := &detonatorMocks.Detonator{}
	mockDetonator.On("Detonate").Return(uid, nil)

	sig1 := makeSignalWithUID("s1", uid)
	sig2 := makeSignalWithUID("s2", uid)

	mockAPI := &ddMocks.DatadogSecuritySignalsAPI{}
	mockAPI.On("SearchSignals", mock.Anything).Return([]datadogV2.SecurityMonitoringSignal{sig1, sig2}, nil)
	mockAPI.On("CloseSignal", mock.Anything).Return(nil)

	runner := &TestRunner{
		Scenarios:  []*Scenario{{Name: "test", Detonator: mockDetonator}},
		Interval:   10 * time.Millisecond,
		SignalsAPI: mockAPI,
	}

	start := time.Now()
	result := runner.DiscoverScenario(runner.Scenarios[0], DiscoveryOptions{
		Timeout:    10 * time.Second,
		MinSignals: 2,
	})
	assert.NoError(t, result.Error)
	assert.Len(t, result.Signals, 2)
	assert.True(t, time.Since(start) < 5*time.Second)
}

func TestDiscoverScenario_Dedup(t *testing.T) {
	uid := "uid-dedup"
	mockDetonator := &detonatorMocks.Detonator{}
	mockDetonator.On("Detonate").Return(uid, nil)

	sig := makeSignalWithUID("same-id", uid)

	callCount := 0
	mockAPI := &ddMocks.DatadogSecuritySignalsAPI{}
	mockAPI.On("SearchSignals", mock.Anything).Return(
		func(query string) []datadogV2.SecurityMonitoringSignal {
			callCount++
			if callCount <= 2 {
				return []datadogV2.SecurityMonitoringSignal{sig}
			}
			return []datadogV2.SecurityMonitoringSignal{sig}
		},
		func(query string) error { return nil },
	)
	mockAPI.On("CloseSignal", mock.Anything).Return(nil)

	runner := &TestRunner{
		Scenarios:  []*Scenario{{Name: "test", Detonator: mockDetonator}},
		Interval:   10 * time.Millisecond,
		SignalsAPI: mockAPI,
	}

	result := runner.DiscoverScenario(runner.Scenarios[0], DiscoveryOptions{Timeout: 100 * time.Millisecond})
	assert.NoError(t, result.Error)
	assert.Len(t, result.Signals, 1)
	assert.Equal(t, "same-id", result.Signals[0].SignalID)
}

func TestDiscoverScenario_DetonationError(t *testing.T) {
	mockDetonator := &detonatorMocks.Detonator{}
	mockDetonator.On("Detonate").Return("", errors.New("boom"))

	runner := &TestRunner{
		Scenarios: []*Scenario{{Name: "test", Detonator: mockDetonator}},
		Interval:  10 * time.Millisecond,
	}

	result := runner.DiscoverScenario(runner.Scenarios[0], DiscoveryOptions{Timeout: 50 * time.Millisecond})
	assert.Error(t, result.Error)
	assert.Equal(t, "boom", result.Error.Error())
}

func TestRunDiscover(t *testing.T) {
	uid := "uid-run"
	mockDetonator := &detonatorMocks.Detonator{}
	mockDetonator.On("Detonate").Return(uid, nil)

	signals := make([]datadogV2.SecurityMonitoringSignal, 3)
	for i := range signals {
		signals[i] = makeSignalWithUID("sig-"+strconv.Itoa(i), uid)
	}

	mockAPI := &ddMocks.DatadogSecuritySignalsAPI{}
	mockAPI.On("SearchSignals", mock.Anything).Return(signals, nil)
	mockAPI.On("CloseSignal", mock.Anything).Return(nil)

	runner := &TestRunner{
		Scenarios: []*Scenario{
			{Name: "scenario-1", Detonator: mockDetonator},
			{Name: "scenario-2", Detonator: mockDetonator},
		},
		Interval:   10 * time.Millisecond,
		SignalsAPI: mockAPI,
	}

	results := runner.RunDiscover(DiscoveryOptions{Timeout: 50 * time.Millisecond, MinSignals: 3})
	assert.Len(t, results, 2)
	for _, r := range results {
		assert.NoError(t, r.Error)
		assert.Len(t, r.Signals, 3)
	}
}
