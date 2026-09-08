package threatest

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/datadog/threatest/pkg/threatest/matchers"
	"github.com/datadog/threatest/pkg/threatest/querybuilder"
	log "github.com/sirupsen/logrus"
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
	return m.RunWithContext(context.Background())
}

func (m *TestRunner) RunWithContext(ctx context.Context) error {
	m.buildScenarios()

	failedScenarios := map[string]error{}
	for i := range m.Scenarios {
		scenario := m.Scenarios[i]
		if err := m.runScenario(ctx, scenario); err != nil {
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

func (m *TestRunner) runScenario(ctx context.Context, scenario *Scenario) error {
	correlationID, err := scenario.Detonator.Detonate()
	if err != nil {
		return err
	}
	//TODO: When to clean? If we don't wait a bit, we risk missing signals that were generated after our assertion matched
	defer m.cleanupScenario(ctx, scenario, correlationID)

	if scenario.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, time.Now().Add(scenario.Timeout))
		defer cancel()
	}

	log.Debugf("Scenario '%s' detonated", scenario.Name)

	tasks := m.buildAssertionTasks(ctx, scenario, correlationID)

	var mu sync.Mutex
	var failures []string
	var wg sync.WaitGroup

	for i := range tasks {
		t := tasks[i]
		wg.Go(func() {
			if err := t(); err != nil {
				mu.Lock()
				failures = append(failures, err.Error())
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "\n"))
	}
	log.Printf("%s: All assertions passed\n", scenario.Name)
	return nil
}

func (m *TestRunner) buildAssertionTasks(ctx context.Context, scenario *Scenario, correlationID string) []func() error {
	var tasks []func() error

	for i := range scenario.TelemetryAssertions {
		a := &scenario.TelemetryAssertions[i]
		if a.Discover {
			tasks = append(tasks, func() error {
				m.collect(ctx, a, correlationID)
				log.Printf("%s: Discovered %d %s\n", scenario.Name, len(a.Discovered), a.Matcher.String())
				for id, e := range a.Discovered {
					log.Printf("    [%s] %s", id, matchers.DescribeEvent(e))
				}
				return nil
			})
			continue
		}

		tasks = append(tasks, func() error {
			found, err := m.pollAssert(ctx, a.Matcher.HasExpected, correlationID)
			if err != nil {
				return fmt.Errorf("%s: error checking %s: %w", scenario.Name, a.Matcher.String(), err)
			}
			if !found {
				return fmt.Errorf("%s: did not find %s", scenario.Name, a.Matcher.String())
			}
			return nil
		})
	}

	return tasks
}

func (m *TestRunner) pollAssert(ctx context.Context, hasExpected func(context.Context, string) (bool, error), correlationID string) (bool, error) {
	for {
		if ctx.Err() != nil {
			return false, nil
		}
		found, err := hasExpected(ctx, correlationID)
		if err != nil {
			return false, err
		}
		if found {
			return true, nil
		}
		select {
		case <-ctx.Done():
			return false, nil
		case <-time.After(m.Interval):
		}
	}
}

func (m *TestRunner) collect(ctx context.Context, a *TelemetryAssertion, correlationID string) {
	a.Discovered = make(map[string]matchers.ThreatestEvent)
	for {
		if ctx.Err() != nil {
			return
		}
		var results map[string]matchers.ThreatestEvent
		var err error
		if a.Query != "" {
			resolved := querybuilder.SubstituteQuery(a.Query, querybuilder.CorrelationVars{CorrelationID: correlationID})
			results, err = a.Matcher.Search(ctx, resolved)
		} else {
			results, err = a.Matcher.Related(ctx, correlationID)
		}
		if err != nil {
			log.Warnf("discovery error: %v", err)
		} else {
			maps.Copy(a.Discovered, results) // In case of error, results is nil, so this is a no-op
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(m.Interval):
		}
	}
}

func (m *TestRunner) cleanupScenario(ctx context.Context, scenario *Scenario, correlationID string) {
	for i := range scenario.TelemetryAssertions {
		if scenario.TelemetryAssertions[i].Discover {
			continue
		}
		// TODO (code smell): this shouldn't be specific to a single assertion?
		if err := scenario.TelemetryAssertions[i].Matcher.Cleanup(ctx, correlationID); err != nil {
			log.Warnf("warning: failed to clean up generated signals: %s", err.Error())
		}
	}
}
