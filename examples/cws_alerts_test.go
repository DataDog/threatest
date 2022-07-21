package examples

import (
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader" // Note: This import is needed
	. "github.com/datadog/threatest/pkg/threatest"
	. "github.com/datadog/threatest/pkg/threatest/detonators"
	. "github.com/datadog/threatest/pkg/threatest/matchers/datadog"
	"github.com/stretchr/testify/require"
	"testing"
)

/*
func TestCWSAlerts(t *testing.T) {
	ssh, err := NewSSHCommandExecutor("test-box", "", "")
	if err != nil {
		t.Fatal(err)
	}

	threatest := Threatest()

	threatest.Scenario("curl to metadata service").
		WhenDetonating(NewCommandDetonator(ssh, "curl http://169.254.169.254 --connect-timeout 5")).
		Expect(DatadogSecuritySignal("EC2 Instance Metadata Service Accessed via Network Utility"))

	threatest.Scenario("Java spawning shell").
		WhenDetonating(NewCommandDetonator(ssh, `cp /bin/bash /tmp/java; /tmp/java -c "curl 1.1.1.1"`)).
		Expect(DatadogSecuritySignal("Java process spawned shell/utility"))

	require.Nil(t, threatest.Run())
}

//*/

/*
	This function shows a way of writing data-driven Go tests, which has the nice property of parallelization
	and showing errors per test case. It should be a little less easy to write, but faster
*/
func TestCWSAlertsV2(t *testing.T) {
	testCases := []struct {
		Name               string
		Command            string
		ExpectedSignalName string
	}{
		{"curl to metadata service", "curl http://169.254.169.254 --connect-timeout 5", "EC2 Instance Metadata Service Accessed via Network Utility"},
		{"java spawns shell", `cp /bin/bash /tmp/java; /tmp/java -c "curl 1.1.1.1"`, "Java process spawned shell/utility"},
	}
	ssh, err := NewSSHCommandExecutor("test-box", "", "")
	if err != nil {
		t.Fatal("Unable to connect over SSH: " + err.Error())
	}

	for i := range testCases {
		test := testCases[i]
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			threatest := Threatest()
			threatest.Scenario(test.Name).WhenDetonating(NewCommandDetonator(ssh, test.Command)).Expect(DatadogSecuritySignal(test.ExpectedSignalName))
			require.Nil(t, threatest.Run())
		})
	}
}
