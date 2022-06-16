package main

import (
	. "github.com/datadog/e2e/pkg/e2e"
	. "github.com/datadog/e2e/pkg/integrations"
	_ "github.com/datadog/stratus-red-team/pkg/stratus/loader" // Note: This import is needed
	"testing"
)

func TestAlerts(t *testing.T) {
	ssh, err := NewSSHCommandExecutor("test-box", "", "")
	if err != nil {
		t.Fatal(err)
	}

	runner := TestRunner{}

	runner.Scenario("curl to metadata service").
		WhenDetonating(NewCommandDetonator(ssh, "curl http://169.254.169.254 --connect-timeout 5")).
		Expect(DatadogSecuritySignal("EC2 Instance Metadata Service Accessed via Network Utility"))

	runner.Scenario("Java spawning shell").
		WhenDetonating(NewCommandDetonator(ssh, `cp /bin/bash /tmp/java; /tmp/java -c "curl 1.1.1.1"`)).
		Expect(DatadogSecuritySignal("Java process spawned shell/utility"))

	/*runner.Scenario("AWS console login").
	WhenDetonating(StratusRedTeamTechnique("aws.initial-access.console-login-without-mfa")).
	Expect(DatadogSecuritySignal("AWS Console login without MFA").WithSeverity("medium")).
	Expect(DatadogSecuritySignal("An IAM user was created")).
	WithTimeout(10 * time.Minute)*/

	/*runner.Scenario("AWS persistence IAM user").
	WhenDetonating(StratusRedTeamTechnique("aws.persistence.iam-create-admin-user")).
	Expect(DatadogSecuritySignal("An IAM user was created")).
	WithTimeout(10 * time.Minute)*/

	runner.Run(t)

	//TODO: Problem, all assertions for a given platform are executed independently
	// This means we hit the same API and get the same results a lot of times

	// TODO: CWS container executor

	//TODO is parallel access an issue for SRT?

	//TODO can we reuse terratest ssh instead
}
