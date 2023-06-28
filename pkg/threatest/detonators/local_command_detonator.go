package detonators

import (
	"github.com/hashicorp/go-uuid"
	log "github.com/sirupsen/logrus"
	"os/exec"
)

type LocalCommandExecutor struct{}

func (m *LocalCommandExecutor) RunCommand(command string) (string, error) {
	log.Infof("Executing %s", command)
	id, _ := uuid.GenerateUUID()
	_, err := exec.Command("bash", "-c", FormatCommand(command, id)).Output()
	if err != nil {
		return "", err
	}
	return id, nil
}
