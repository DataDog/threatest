package threatest

import (
	"github.com/datadog/threatest/pkg/threatest/detonators"
	"github.com/datadog/threatest/pkg/threatest/matchers"
	log "github.com/sirupsen/logrus"
	"time"
)

type Scenario struct {
	Name                string
	Detonator           detonators.Detonator
	Timeout             time.Duration
	TelemetryAssertions []TelemetryAssertion

	// Deprecated: use TelemetryAssertions. Kept for backward compatibility with
	// scenarios that use Expect() with AlertGeneratedMatcher. Converted to
	// TelemetryAssertions at build time.
	Assertions []matchers.TelemetryMatcher
}

type TelemetryAssertion struct {
	Matcher    matchers.TelemetryMatcher
	Discover   bool
	Query      string
	Discovered map[string]matchers.ThreatestEvent
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

func (m *ScenarioBuilder) Expect(matcher matchers.TelemetryMatcher) *ScenarioBuilder {
	m.TelemetryAssertions = append(m.TelemetryAssertions, TelemetryAssertion{Matcher: matcher})
	return m
}

func (m *ScenarioBuilder) ExpectTelemetry(assertion TelemetryAssertion) *ScenarioBuilder {
	m.TelemetryAssertions = append(m.TelemetryAssertions, assertion)
	return m
}

func (m *ScenarioBuilder) Build() *Scenario {
	s := &Scenario{
		Name:                m.Name,
		Detonator:           m.Detonator,
		Timeout:             m.Timeout,
		TelemetryAssertions: m.TelemetryAssertions,
	}
	if len(m.Assertions) > 0 {
		log.Warnf("scenario '%s' uses deprecated Assertions field, migrating to TelemetryAssertions", m.Name)
		for _, a := range m.Assertions {
			s.TelemetryAssertions = append(s.TelemetryAssertions, TelemetryAssertion{Matcher: a})
		}
	}
	return s
}
