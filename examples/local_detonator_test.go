package examples

import (
	"fmt"
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader" // Note: This import is needed
	. "github.com/datadog/threatest/pkg/threatest"
	. "github.com/datadog/threatest/pkg/threatest/detonators"
	. "github.com/datadog/threatest/pkg/threatest/matchers/datadog"
	"testing"
	"time"
)

func TestLocalDetonator(t *testing.T) {
	localExecutor := &LocalCommandExecutor{}

	threatest := Threatest()

	threatest.Scenario("curl to metadata service").
		WhenDetonating(NewCommandDetonator(localExecutor, "curl http://169.254.169.254 --connect-timeout 5")).
		Expect(DatadogSecuritySignal("EC2 Instance Metadata Service Accessed via Network Utility")).
		WithTimeout(1 * time.Second)

	threatest.Scenario("Java spawning shell").
		WhenDetonating(NewCommandDetonator(localExecutor, `cp /bin/bash /tmp/java; /tmp/java -c "curl 1.1.1.1"`)).
		Expect(DatadogSecuritySignal("Java process spawned shell/utility")).
		WithTimeout(1 * time.Second)

	if err := threatest.Run(); err != nil {
		fmt.Println("Test failed: " + err.Error())
		t.Fail()
	}
}
