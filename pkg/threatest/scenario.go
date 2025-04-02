package threatest

import (
	"github.com/datadog/threatest/pkg/threatest/detonators"
	"github.com/datadog/threatest/pkg/threatest/matchers"
	"time"
)

type Scenario struct {
	Name          string
	Detonator     detonators.Detonator
	Timeout       time.Duration
	CheckInterval time.Duration // Duration of time between checks for all assertions
	Assertions    []matchers.AlertGeneratedMatcher
}

type ScenarioBuilder struct {
	Scenario
}

func (m *ScenarioBuilder) WhenDetonating(detonation detonators.Detonator) *ScenarioBuilder {
	m.Detonator = detonation
	return m
}

func (m *ScenarioBuilder) WithTimeout(timeout time.Duration) *ScenarioBuilder {
	m.Timeout = timeout
	return m
}

func (m *ScenarioBuilder) WithCheckInterval(interval time.Duration) *ScenarioBuilder {
	m.CheckInterval = interval
	return m
}

func (m *ScenarioBuilder) Expect(assertion matchers.AlertGeneratedMatcher) *ScenarioBuilder {
	m.Assertions = append(m.Assertions, assertion)
	return m
}

func (m *ScenarioBuilder) Build() *Scenario {
	return &Scenario{
		Name:          m.Name,
		Detonator:     m.Detonator,
		Timeout:       m.Timeout,
		CheckInterval: m.CheckInterval,
		Assertions:    m.Assertions,
	}
}
