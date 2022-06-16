package examples

import (
	_ "github.com/datadog/stratus-red-team/pkg/stratus/loader" // Note: This import is needed
	. "github.com/datadog/threatest/pkg/threatest"
	. "github.com/datadog/threatest/pkg/threatest/detonators"
	. "github.com/datadog/threatest/pkg/threatest/matchers/datadog"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestCloudSIEMAWSAlerts(t *testing.T) {
	runner := TestRunner{}

	runner.Scenario("AWS console login").
		WhenDetonating(StratusRedTeamTechnique("aws.initial-access.console-login-without-mfa")).
		Expect(DatadogSecuritySignal("AWS Console login without MFA").WithSeverity("medium")).
		Expect(DatadogSecuritySignal("An IAM user was created")).
		WithTimeout(10 * time.Minute)

	runner.Scenario("AWS persistence IAM user").
		WhenDetonating(StratusRedTeamTechnique("aws.persistence.iam-create-admin-user")).
		Expect(DatadogSecuritySignal("An IAM user was created")).
		WithTimeout(10 * time.Minute)

	require.Nil(t, runner.Run())
}
