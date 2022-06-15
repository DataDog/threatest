package main

import (
	. "github.com/datadog/e2e/pkg/e2e"
	. "github.com/datadog/e2e/pkg/integrations"
	_ "github.com/datadog/stratus-red-team/pkg/stratus/loader" // Note: This import is needed
	"testing"
	"time"
)

func TestAlerts(t *testing.T) {
	WhenDetonating("aws.initial-access.console-login-without-mfa").
		Using(StratusRedTeam()).
		Expect(DatadogSecuritySignal("AWS Console login without MFA").WithSeverity("medium")).
		WithTimeout(10 * time.Minute).
		Run(t)
}
