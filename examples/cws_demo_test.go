package examples

import (
	"github.com/datadog/threatest/pkg/threatest/matchers/datadog"
	"testing"

	_ "github.com/datadog/stratus-red-team/pkg/stratus/loader" // Note: This import is needed
	. "github.com/datadog/threatest/pkg/threatest"
	. "github.com/datadog/threatest/pkg/threatest/detonators"
)

func TestMyCWSAlerts(t *testing.T) {
	ssh, _ := NewSSHCommandExecutor("test-box", "", "")
	threatest := Threatest()

	threatest.Scenario("curl to metadata service").
		WhenDetonating(NewCommandDetonator(ssh, "curl http://169.254.169.254 --connect-timeout 5")).
		Expect(datadog.DatadogSecuritySignal("EC2 Instance Metadata Service Accessed via Network Utility"))

	threatest.Run()

}
