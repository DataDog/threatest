package atomic

import (
	"fmt"
	"strings"
)

func (t *Test) FormatCommand(arguments map[string]string) (string, error) {
	if t.Executor.Name != "bash" {
		return "", fmt.Errorf("invalid executor `%s`, only `bash` is currently supported", t.Executor.Name)
	}

	if t.Executor.Command == nil {
		return "", fmt.Errorf("no command was specified for this test")
	}

	// TODO: handle dependencies install
	// for _, dependency := range t.Dependencies {
	// 	t.InterpolateCommand(dependency.PreReqCommand, arguments)
	// 	t.InterpolateCommand(dependency.GetPreReqCommand, arguments)
	// }

	// TODO: handle additional files management

	return t.interpolateCommand(*t.Executor.Command, arguments), nil

	// TODO: handle cleanup command
	// if t.Executor.CleanupCommand != nil {
	// 	t.InterpolateCommand(*t.Executor.CleanupCommand, arguments)
	// }
}

func (t *Test) interpolateCommand(command string, arguments map[string]string) string {
	for parameterName, parameterDefinition := range t.InputArguments {
		var parameterValue string

		if _, ok := arguments[parameterName]; ok {
			parameterValue = arguments[parameterName]
		} else if parameterDefinition.Default != nil {
			parameterValue = *parameterDefinition.Default
		}

		command = strings.ReplaceAll(command, fmt.Sprintf("${%s}", parameterName), parameterValue)
	}

	return command
}
