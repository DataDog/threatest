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

	// Go over each
	remainingAssertions := m.Scenario.Assertions
	defer func() {
		err := m.Scenario.Assertions[0].Cleanup(detonationUid)
		if err != nil {
			t.Log("warning: failed to clean up generated signals: " + err.Error())
		}
	}() // TODO: this shouldn't be specific to a single assertion

	for len(remainingAssertions) > 0 && (m.Timeout == 0 || !time.Now().After(start.Add(m.Timeout))) {
		for i := range remainingAssertions {
			assertion := remainingAssertions[i]
			hasAlert, err := assertion.HasExpectedAlert(detonationUid)
			if err != nil {
				t.Error(err)
			}
			if hasAlert {
				timeSpentStr := strconv.Itoa(int(time.Since(start).Seconds()))
				log.Printf("Confirmed that the expected signal was created in Datadog (took %s seconds). Archiving it\n", timeSpentStr)

				// Remove assertion. c.f.https://stackoverflow.com/questions/37334119/how-to-delete-an-element-from-a-slice-in-golang
				numAssertions := len(remainingAssertions)
				remainingAssertions[i] = remainingAssertions[numAssertions-1]
				remainingAssertions = remainingAssertions[:numAssertions-1]
			}
		}
		time.Sleep(interval)
	}

	if len(remainingAssertions) > 0 {
		t.Error(strconv.Itoa(len(remainingAssertions)) + " assertions did not pass")
	} else {
		t.Log("All assertions passed")
	}
}
