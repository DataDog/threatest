package threatest

import (
	"github.com/datadog/threatest/pkg/threatest/matchers"
	"strconv"
	"testing"
	"time"
)

type TestRunner struct {
	Builders  []*ScenarioBuilder
	Scenarios []*Scenario
}

func (m *TestRunner) Scenario(name string) *ScenarioBuilder {
	builder := ScenarioBuilder{}
	builder.Name = name
	builder.Timeout = 10 * time.Minute // default timeout
	m.Builders = append(m.Builders, &builder)
	return &builder
}

func (m *TestRunner) Add(scenario *ScenarioBuilder) {
	m.Scenarios = append(m.Scenarios, scenario.Build())
}

func (m *TestRunner) Run(t *testing.T) {
	for i := range m.Builders {
		scenario := m.Builders[i].Build()
		t.Run(scenario.Name, func(t *testing.T) {
			t.Parallel()
			m.runScenario(t, scenario)
		})
	}
}

func (m *TestRunner) runScenario(t *testing.T, scenario *Scenario) {
	detonationUid, err := scenario.Detonator.Detonate()
	if err != nil {
		t.Error(err)
		return
	}
	start := time.Now()
	const interval = 2 * time.Second

	if len(scenario.Assertions) == 0 {
		t.Log("No assertion, test passed")
		return
	}

	// Build a queue containing all assertions
	remainingAssertions := make(chan matchers.AlertGeneratedMatcher, len(scenario.Assertions))
	for i := range scenario.Assertions {
		remainingAssertions <- scenario.Assertions[i]
	}

	defer func() {
		err := scenario.Assertions[0].Cleanup(detonationUid)
		if err != nil {
			t.Log("warning: failed to clean up generated signals: " + err.Error())
		}
	}() // TODO: this shouldn't be specific to a single assertion

	hasDeadline := scenario.Timeout > 0
	deadline := start.Add(scenario.Timeout)
	for len(remainingAssertions) > 0 {
		if hasDeadline && time.Now().After(deadline) {
			t.Logf("%s: timeout exceeded waiting for alerts (%d alerts not generated)", scenario.Name, len(remainingAssertions))
			break
		}

		assertion := <-remainingAssertions
		hasAlert, err := assertion.HasExpectedAlert(detonationUid)
		if err != nil {
			t.Error(err)
		}
		if hasAlert {
			timeSpentStr := strconv.Itoa(int(time.Since(start).Seconds()))
			t.Logf("%s: Confirmed that the expected signal (%s) was created in Datadog (took %s seconds).\n", scenario.Name, assertion.String(), timeSpentStr)
		} else {
			// requeue assertion
			remainingAssertions <- assertion
			time.Sleep(interval) //TODO: currently sleeps between every assertion, should be only 1 per pass
		}
	}

	if numRemainingAssertions := len(remainingAssertions); numRemainingAssertions > 0 {
		t.Logf("%s: %d assertions did not pass", scenario.Name, numRemainingAssertions)
		for i := 0; i < numRemainingAssertions; i++ {
			assertion := <-remainingAssertions
			t.Logf("=> Did not find %s", assertion)
		}
		t.Fail()
	} else {
		t.Logf("%s: All assertions passed", scenario.Name)
	}
}

func (m *TestRunner) CleanupScenario(t *testing.T, scenario *Scenario, detonationUid string) {
	err := scenario.Assertions[0].Cleanup(detonationUid)
	if err != nil {
		t.Log("warning: failed to clean up generated signals: " + err.Error())
	}
	// TODO: this shouldn't be specific to a single assertion?
}
