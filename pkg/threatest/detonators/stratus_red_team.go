package detonators

import (
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader"
	stratusrunner "github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
	log "github.com/sirupsen/logrus"
)

func StratusRedTeamTechnique(ttp string) *StratusRedTeamDetonator {
	return &StratusRedTeamDetonator{
		Technique: stratus.GetRegistry().GetAttackTechniqueByName(ttp),
	}
}

type StratusRedTeamDetonator struct {
	Technique *stratus.AttackTechnique
}

func (m *StratusRedTeamDetonator) Detonate() (string, error) {
	// detonate a specific stratus red team TTP
	ttp := m.Technique
	stratusRunner := stratusrunner.NewRunner(ttp, stratusrunner.StratusRunnerNoForce)

	log.Infof("Detonating '%s' with Stratus Red Team", m.Technique.ID)

	defer stratusRunner.CleanUp()

	if _, err := stratusRunner.WarmUp(); err != nil {
		return "", err
	}
	if err := stratusRunner.Detonate(); err != nil {
		return "", err
	}

	executionId := stratusRunner.GetUniqueExecutionId()
	log.Infof("Execution ID: %s", executionId)

	return executionId, nil

}
