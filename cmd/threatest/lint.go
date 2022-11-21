package main

import (
	"errors"
	"fmt"
	"github.com/datadog/threatest/pkg/threatest"
	"github.com/datadog/threatest/pkg/threatest/parser"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
)

// LintCommand implements syntax verification of a Threatest scenario file
type LintCommand struct {
	InputFiles []string
}

func (m *LintCommand) Do() error {
	if len(m.InputFiles) == 0 {
		return errors.New("please provide at least 1 scenario")
	}
	var numScenarios = 0
	for _, inputFile := range m.InputFiles {
		rawScenario, err := os.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("unable to read input file %s: %v", inputFile, err)
		}
		scenarios, err := parser.Parse(rawScenario, "unused", "", "")
		if err != nil {
			return fmt.Errorf("unable to parse input file %s: %v", inputFile, err)
		}
		for _, scenario := range scenarios {
			if err := validateScenario(scenario); err != nil {
				return fmt.Errorf("invalid scenario '%s': %s", scenario.Name, err.Error())
			}
		}
		numScenarios += len(scenarios)
	}
	log.Infof("All %d scenarios are syntaxically valid", numScenarios)
	return nil
}

func validateScenario(scenario *threatest.Scenario) error {
	if scenario.Detonator == nil {
		return errors.New("no detonator defined")
	}
	if len(scenario.Assertions) == 0 {
		return errors.New("no assertion defined")
	}
	return nil
}

func NewLintCommand() *cobra.Command {
	lintCmd := &cobra.Command{
		Use:          "lint",
		Short:        "Validate the format of scenarios",
		SilenceUsage: true,
		Example:      "lint /path/to/scenario/1 [/path/to/scenario/2]...",
		RunE: func(cmd *cobra.Command, args []string) error {
			command := LintCommand{
				InputFiles: args,
			}
			return command.Do()
		},
	}

	return lintCmd
}
