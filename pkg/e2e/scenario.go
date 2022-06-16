package e2e

import (
	"time"
)

type Scenario struct {
	Name       string
	Detonator  DetonatorV2
	Timeout    time.Duration
	Assertions []AlertGeneratedAssertion
}

type ScenarioBuilder struct {
	Scenario
}

func (m *ScenarioBuilder) WhenDetonating(detonation DetonatorV2) *ScenarioBuilder {
	m.Detonator = detonation
	return m
}

func (m *ScenarioBuilder) WithTimeout(timeout time.Duration) *ScenarioBuilder {
	m.Timeout = timeout
	return m
}

func (m *ScenarioBuilder) Expect(assertion AlertGeneratedAssertion) *ScenarioBuilder {
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
