package threatest

import (
	"errors"
	"fmt"
	"github.com/datadog/threatest/pkg/threatest/matchers"
	"log"
	"strconv"
	"strings"
	"time"
)

type TestRunner struct {
	Builders  []*ScenarioBuilder
	Scenarios []*Scenario
	Interval  time.Duration
}

func Threatest() *TestRunner {
	return &TestRunner{Interval: 2 * time.Second}
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

func (m *TestRunner) Run() error {
	m.buildScenarios()

	// Run every scenario one by one
	failedScenarios := map[string]error{}
	for i := range m.Scenarios {
		scenario := m.Scenarios[i]
		if err := m.runScenario(scenario); err != nil {
			failedScenarios[scenario.Name] = err
		}
	}

	if len(failedScenarios) > 0 {
		var errorMessage strings.Builder
		errorMessage.WriteString("At least one scenario failed:\n\n")
		for scenario, err := range failedScenarios {
			errorMessage.WriteString(scenario)
			errorMessage.WriteString(" returned: ")
			errorMessage.WriteString(err.Error())
			errorMessage.WriteRune('\n')
		}
		return errors.New(errorMessage.String())
	}

	return nil
}

func (m *TestRunner) buildScenarios() {
	if len(m.Scenarios) == 0 {
		for i := range m.Builders {
			m.Scenarios = append(m.Scenarios, m.Builders[i].Build())
		}
	}
}

func (m *TestRunner) runScenario(scenario *Scenario) error {
	detonationUid, err := scenario.Detonator.Detonate()
	if err != nil {
		return err
	}
	//TODO: When to clean? If we don't wait a bit, we risk missing signals that were generated after our assertion matched
	defer m.CleanupScenario(scenario, detonationUid)

	start := time.Now()

	if len(scenario.Assertions) == 0 {
		return nil
	}

	// Build a queue containing all assertions
	remainingAssertions := make(chan matchers.AlertGeneratedMatcher, len(scenario.Assertions))
	for i := range scenario.Assertions {
		remainingAssertions <- scenario.Assertions[i]
	}

	hasDeadline := scenario.Timeout > 0
	deadline := start.Add(scenario.Timeout)
	for len(remainingAssertions) > 0 {
		if hasDeadline && time.Now().After(deadline) {
			log.Printf("%s: timeout exceeded waiting for alerts (%d alerts not generated)\n", scenario.Name, len(remainingAssertions))
			break
		}

		assertion := <-remainingAssertions
		hasAlert, err := assertion.HasExpectedAlert(detonationUid)
		if err != nil {
			return err
		}
		if hasAlert {
			timeSpentStr := strconv.Itoa(int(time.Since(start).Seconds()))
			log.Printf("%s: Confirmed that the expected signal (%s) was created in Datadog (took %s seconds).\n", scenario.Name, assertion.String(), timeSpentStr)
		} else {
			// requeue assertion
			remainingAssertions <- assertion
			time.Sleep(m.Interval)
		}
	}

	if numRemainingAssertions := len(remainingAssertions); numRemainingAssertions > 0 {
		errText := fmt.Sprintf("%s: %d assertions did not pass", scenario.Name, numRemainingAssertions)
		for i := 0; i < numRemainingAssertions; i++ {
			assertion := <-remainingAssertions
			errText += fmt.Sprintf("\n => Did not find %s", assertion)
		}
		return errors.New(errText)
	} else {
		log.Printf("%s: All assertions passed\n", scenario.Name)
	}

	return nil
}

func (m *TestRunner) CleanupScenario(scenario *Scenario, detonationUid string) {
	if len(scenario.Assertions) == 0 {
		return
	}

	err := scenario.Assertions[0].Cleanup(detonationUid)
	if err != nil {
		log.Println("warning: failed to clean up generated signals: " + err.Error())
	}
	// TODO (code smell): this shouldn't be specific to a single assertion?
}
