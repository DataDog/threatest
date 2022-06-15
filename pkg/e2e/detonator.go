package e2e

import (
	"errors"
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

func StratusRedTeam() *StratusRedTeamDetonator {
	return &StratusRedTeamDetonator{}
}

type StratusRedTeamDetonator struct{}

// todo separate pkg from logic

func (m *StratusRedTeamDetonator) Detonate(attackTechnique string) (string, error) {
	// detonate a specific stratus red team TTP
	ttp := stratus.GetRegistry().GetAttackTechniqueByName(attackTechnique)
	if ttp == nil {
		return "", errors.New("unknown attack technique " + attackTechnique)
	}
	stratusRunner := stratusrunner.NewRunner(ttp, stratusrunner.StratusRunnerNoForce)

	fmt.Println("Detonating '" + attackTechnique + "' with Stratus Red Team")

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
