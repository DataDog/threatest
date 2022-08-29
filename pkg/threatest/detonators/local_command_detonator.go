package detonators

import (
	"fmt"
	"github.com/hashicorp/go-uuid"
	"os/exec"
)

type LocalCommandExecutor struct{}

func (m *LocalCommandExecutor) RunCommand(command string) (string, error) {
	fmt.Println("Executing " + command)
	id, _ := uuid.GenerateUUID()
	_, err := exec.Command("bash", "-c", FormatCommand(command, id)).Output()
	if err != nil {
		return "", err
	}
	return id, nil
}
