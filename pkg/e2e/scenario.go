package e2e

import (
	. "github.com/datadog/e2e/pkg/e2e/detonators"
	"github.com/datadog/e2e/pkg/e2e/matchers"
	"time"
)

type Scenario struct {
	Name       string
	Detonator  Detonator
	Timeout    time.Duration
	Assertions []matchers.AlertGeneratedMatcher
}

type ScenarioBuilder struct {
	Scenario
}

func (m *ScenarioBuilder) WhenDetonating(detonation Detonator) *ScenarioBuilder {
	m.Detonator = detonation
	return m
}

func (m *ScenarioBuilder) WithTimeout(timeout time.Duration) *ScenarioBuilder {
	m.Timeout = timeout
	return m
}

func (m *ScenarioBuilder) Expect(assertion matchers.AlertGeneratedMatcher) *ScenarioBuilder {
	m.Assertions = append(m.Assertions, assertion)
	return m
}

func (m *ScenarioBuilder) Build() *Scenario {
	return &Scenario{
		Name:       m.Name,
		Detonator:  m.Detonator,
		Timeout:    m.Timeout,
		Assertions: m.Assertions,
	}
}
