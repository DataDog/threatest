package examples

import (
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader" // Note: This import is needed
	. "github.com/datadog/threatest/pkg/threatest"
	. "github.com/datadog/threatest/pkg/threatest/detonators"
	. "github.com/datadog/threatest/pkg/threatest/matchers/datadog"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestCloudSIEMAWSAlerts(t *testing.T) {
	threatest := Threatest()
	threatest.Interval = 0

	threatest.Scenario("AWS console login").
		WhenDetonating(StratusRedTeamTechnique("aws.initial-access.console-login-without-mfa")).
		Expect(DatadogSecuritySignal("AWS Console login without MFA").WithSeverity("medium")).
		Expect(DatadogSecuritySignal("An IAM user was created")).
		WithTimeout(10 * time.Minute)

	threatest.Scenario("Opening port 22 of a security group to the Internet").
		WhenDetonating(StratusRedTeamTechnique("aws.exfiltration.ec2-security-group-open-port-22-ingress")).
		Expect(DatadogSecuritySignal("Potential administrative port open to the world via AWS security group")).
		WithTimeout(10 * time.Minute)

	threatest.Scenario("Exfiltrating an EBS snapshot").
		WhenDetonating(StratusRedTeamTechnique("aws.exfiltration.ec2-share-ebs-snapshot")).
		Expect(DatadogSecuritySignal("AWS EBS Snapshot possible exfiltration")).
		WithTimeout(10 * time.Minute)

	threatest.Scenario("Disabling CloudTrail through event selectors").
		WhenDetonating(StratusRedTeamTechnique("aws.defense-evasion.cloudtrail-event-selectors")).
		Expect(DatadogSecuritySignal("AWS Disable Cloudtrail with event selectors")).
		WithTimeout(10 * time.Minute)

	require.Nil(t, threatest.Run())
}
