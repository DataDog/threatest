package e2e

import (
	"fmt"
	"log"
	"strconv"
	"testing"
	"time"
)

type Scenario struct {
	AttackTechnique string
	Detonator       Detonator
	Timeout         time.Duration
	Assertions      []AlertGeneratedAssertion
}

//TODO separate domain and running
func (m *ScenarioBuilder) Run(t *testing.T) {
	detonationUid, err := m.Detonator.Detonate(m.Scenario.AttackTechnique)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Println(detonationUid)
	start := time.Now()
	const interval = 2 * time.Second

	for {
		if time.Now().After(start.Add(m.Timeout)) {
			t.Error("timed out waiting for alert")
		}
		hasAlert, err := m.Scenario.Assertions[0].HasExpectedAlert(detonationUid)
		if err != nil {
			t.Error(err)
		}
		if hasAlert {
			timeSpentStr := strconv.Itoa(int(time.Since(start).Seconds()))
			log.Printf("%s: Confirmed that the expected signal was created in Datadog (took %s seconds). Archiving it\n", m.Scenario.AttackTechnique, timeSpentStr)
			err = m.Scenario.Assertions[0].Cleanup(detonationUid) // TODO only supports 1 assertion
			if err != nil {
				t.Log("warning: failed to clean up generated signals: " + err.Error())
			}
			return
		}
		time.Sleep(interval)
	}
}
