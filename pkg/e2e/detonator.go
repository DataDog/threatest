package e2e

import (
	"fmt"
	"github.com/datadog/stratus-red-team/pkg/stratus"
	stratusrunner "github.com/datadog/stratus-red-team/pkg/stratus/runner"
	"io"
	"log"
	"os"
)

type Detonator interface {
	Detonate(string) (string, error)
}

func StratusRedTeamTechnique(ttp string) *StratusRedTeamDetonator {
	return &StratusRedTeamDetonator{
		Technique: stratus.GetRegistry().GetAttackTechniqueByName(ttp),
	}
}

type StratusRedTeamDetonator struct {
	Technique *stratus.AttackTechnique
}

// todo separate pkg from logic

func (m *StratusRedTeamDetonator) Detonate() (string, error) {
	// detonate a specific stratus red team TTP
	ttp := m.Technique
	stratusRunner := stratusrunner.NewRunner(ttp, stratusrunner.StratusRunnerNoForce)

	fmt.Println("Detonating '" + m.Technique.ID + "' with Stratus Red Team")

	log.Default().SetOutput(io.Discard) // suppress output
	defer func() {
		stratusRunner.CleanUp()
		log.Default().SetOutput(os.Stdout) // restore logging
	}()

	_, err := stratusRunner.WarmUp()
	if err != nil {
		return "", err
	}
	err = stratusRunner.Detonate()
	if err != nil {
		return "", err
	}
	return stratusRunner.GetUniqueExecutionId(), nil

}
