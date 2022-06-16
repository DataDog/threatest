package e2e

import (
	"fmt"
	"log"
	"strconv"
	"testing"
	"time"
)

type Scenario struct {
	Detonator  DetonatorV2
	Timeout    time.Duration
	Assertions []AlertGeneratedAssertion
}

type ScenarioBuilder struct {
	Scenario
}

func WhenDetonating(detonation DetonatorV2) *ScenarioBuilder {
	builder := ScenarioBuilder{}
	builder.Detonator = detonation
	return &builder
}

func (m *ScenarioBuilder) WithTimeout(timeout time.Duration) *ScenarioBuilder {
	m.Timeout = timeout
	return m
}

func (m *ScenarioBuilder) Expect(assertion AlertGeneratedAssertion) *ScenarioBuilder {
	m.Assertions = append(m.Assertions, assertion)
	return m
}

//TODO separate domain and running
func (m *ScenarioBuilder) Run(t *testing.T) {
	detonationUid, err := m.Detonator.Detonate()
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println(detonationUid)
	start := time.Now()
	const interval = 2 * time.Second

	if len(m.Scenario.Assertions) == 0 {
		t.Log("No assertion, test passed")
		return
	}

	for {
		if m.Timeout > 0 && time.Now().After(start.Add(m.Timeout)) {
			t.Error("timed out waiting for alert")
		}
		hasAlert, err := m.Scenario.Assertions[0].HasExpectedAlert(detonationUid)
		if err != nil {
			t.Error(err)
		}
		if hasAlert {
			timeSpentStr := strconv.Itoa(int(time.Since(start).Seconds()))
			log.Printf("Confirmed that the expected signal was created in Datadog (took %s seconds). Archiving it\n", timeSpentStr)
			err = m.Scenario.Assertions[0].Cleanup(detonationUid) // TODO only supports 1 assertion
			if err != nil {
				t.Log("warning: failed to clean up generated signals: " + err.Error())
			}
			return
		}
		time.Sleep(interval)
	}
}
