package main

import (
	. "github.com/datadog/e2e/pkg/e2e"
	. "github.com/datadog/e2e/pkg/integrations"

	_ "github.com/datadog/stratus-red-team/pkg/stratus/loader" // Note: This import is needed
	"testing"
)

func TestAlerts(t *testing.T) {
	/*WhenDetonating("aws.initial-access.console-login-without-mfa").
	Using(StratusRedTeam()).
	Expect(DatadogSecuritySignal("AWS Console login without MFA").WithSeverity("medium")).
	WithTimeout(10 * time.Minute).
	Run(t)*/

	ssh, err := NewSSHCommandExecutor("test-box", "", "")
	if err != nil {
		t.Fatal(err)
	}

	//TODO: Orchestration
	// MVP: 1 goroutine per scenario
	// Problem: Many duplicated queries to the Datadog API
	// Solution 2:
	// Pass 1: detonate everything
	// Pass 2: filter through all alerts
	WhenDetonating(NewCommandDetonator(ssh, "curl http://169.254.169.254 --connect-timeout 5")).
		Expect(DatadogSecuritySignal("EC2 Instance Metadata Service Accessed via Network Utility")).
		Run(t)

	WhenDetonating(NewCommandDetonator(ssh, `cp /bin/bash /tmp/java; /tmp/java -c "curl 1.1.1.1"`)).
		Expect(DatadogSecuritySignal("Java process spawned shell/utility")).
		Run(t)

	// TODO: CWS container executor

	/*WhenDetonating(StratusRedTeamTechnique("aws.initial-access.console-login-without-mfa")).
	Expect(DatadogSecuritySignal("AWS Console login without MFA").WithSeverity("medium")).
	WithTimeout(10 * time.Minute).
	Run(t)*/

}
