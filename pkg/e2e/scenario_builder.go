package e2e

import "time"

type ScenarioBuilder struct {
	Scenario
}

func WhenDetonating(attackTechnique string) *ScenarioBuilder {
	builder := ScenarioBuilder{}
	builder.AttackTechnique = attackTechnique
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

func (m *ScenarioBuilder) Using(detonator Detonator) *ScenarioBuilder {
	m.Detonator = detonator
	return m
}
