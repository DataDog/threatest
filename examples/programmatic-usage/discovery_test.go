package programmatic_usage

import (
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader"
	. "github.com/datadog/threatest/pkg/threatest"
	. "github.com/datadog/threatest/pkg/threatest/detonators"
	"github.com/datadog/threatest/pkg/threatest/matchers/datadog/agentevents"
	"github.com/datadog/threatest/pkg/threatest/matchers/datadog/logs"
	. "github.com/datadog/threatest/pkg/threatest/matchers/datadog/signals"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestDiscovery(t *testing.T) {
	threatest := Threatest()
	threatest.Interval = 0

	threatest.Scenario("opening a security group to the Internet").
		WhenDetonating(StratusRedTeamTechnique("aws.exfiltration.ec2-security-group-open-port-22-ingress")).
		Expect(DatadogSecuritySignal("Potential administrative port open to the world via AWS security group")).
		ExpectTelemetry(TelemetryAssertion{
			Matcher:  logs.DatadogLog(logs.WithQuery("source:cloudtrail @http.useragent:*<% .CorrelationID %>*")),
			Discover:   true,
			Query:      "source:cloudtrail @http.useragent:*<% .CorrelationID %>*",
		}).
		WithTimeout(15 * time.Minute)

	threatest.Scenario("curl metadata service").
		WhenDetonating(StratusRedTeamTechnique("aws.initial-access.console-login-without-mfa")).
		ExpectTelemetry(TelemetryAssertion{
			Matcher:  agentevents.DatadogAgentEvent(),
			Discover:   true,
		}).
		WithTimeout(5 * time.Minute)

	require.Nil(t, threatest.Run())
}
