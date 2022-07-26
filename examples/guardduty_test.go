package examples

import (
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader" // Note: This import is needed
	. "github.com/datadog/threatest/pkg/threatest"
	. "github.com/datadog/threatest/pkg/threatest/detonators"
	. "github.com/datadog/threatest/pkg/threatest/matchers/guardduty"

	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestGuardDuty(t *testing.T) {
	threatest := Threatest()

	threatest.Scenario("should trigger guardduty").
		WhenDetonating(StratusRedTeamTechnique("aws.persistence.iam-backdoor-user")).
		Expect(GuardDutyFinding("Persistence:IAMUser/AnomalousBehavior")).
		WithTimeout(30 * time.Minute)

	assert.NoError(t, threatest.Run())
}
