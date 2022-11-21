package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/datadog/threatest/pkg/threatest"
	"github.com/datadog/threatest/pkg/threatest/parser"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"math"
	"os"
	"strconv"
	"time"
)

// RunCommand implements the command to run Threatest test scenarios
type RunCommand struct {
	SSHConfig      *SSHConfiguration
	InputFiles     []string
	Parallelism    int
	JsonOutputFile string
}

type SSHConfiguration struct {
	SSHHost     string
	SSHUsername string
	SSHKey      string
}

type ScenarioRunResult struct {
	Description     string    `json:"description"`
	Success         bool      `json:"isSuccess"`
	ErrorMessage    string    `json:"errorMessage"`
	DurationSeconds float64   `json:"durationSeconds"`
	TimeDetonated   time.Time `json:"timeDetonated"`
	//TODO: We possibly want to add some metadata about the kind of detonation
}

func NewRunCommand() *cobra.Command {
	var sshHost string
	var sshUsername string
	var sshKey string
	var parallelism int
	var jsonOutputFile string

	runCmd := &cobra.Command{
		Use:          "run",
		Short:        "Run Threatest scenarios",
		SilenceUsage: true,
		Example:      "run /path/to/scenario/1 [/path/to/scenario/2]...",
		RunE: func(cmd *cobra.Command, args []string) error {
			command := RunCommand{
				InputFiles:     args,
				Parallelism:    parallelism,
				JsonOutputFile: jsonOutputFile,
				SSHConfig: &SSHConfiguration{
					SSHHost:     sshHost,
					SSHUsername: sshUsername,
					SSHKey:      sshKey,
				},
			}

			return command.Do()
		},
	}

	runCmd.Flags().StringVarP(&sshHost, "ssh-host", "", os.Getenv("THREATEST_SSH_HOST"), "SSH host to connect to for remote command detonation. Can also be specified through THREATEST_SSH_HOST")
	runCmd.Flags().StringVarP(&sshUsername, "ssh-username", "", os.Getenv("THREATEST_SSH_USERNAME"), "SSH username to use for remote command detonation  (leave empty to use system configuration). Can also be specified through THREATEST_SSH_USERNAME")
	runCmd.Flags().StringVarP(&sshKey, "ssh-key", "", os.Getenv("THREATEST_SSH_KEY"), "SSH keypair to use for remote command detonation (leave empty to use system configuration). Can also be specified through THREATEST_SSH_KEY. Only unencrypted keys are currently supported")
	runCmd.Flags().StringVarP(&jsonOutputFile, "output", "o", "", "Write JSON test results to the specified file")
	runCmd.Flags().IntVarP(&parallelism, "max-parallelism", "", getDefaultParallelism(), "Maximal parallelism to run the scenarios with. Can also be set through THREATEST_MAX_PARALLELISM")

	return runCmd
}

func getDefaultParallelism() int {
	const DefaultParallelism = 5
	if parallelism, isSet := os.LookupEnv("THREATEST_MAX_PARALLELISM"); isSet {
		parsedParallelism, err := strconv.Atoi(parallelism)
		if err != nil {
			log.Fatalf("unable to convert max parallelism '%s' to integer: %v", parallelism, err)
		}
		return parsedParallelism
	}
	return DefaultParallelism
}

func (m *RunCommand) Do() error {
	if err := m.Validate(); err != nil {
		return err
	}

	var allScenarios []*threatest.Scenario

	for _, inputFile := range m.InputFiles {
		rawScenario, err := os.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("unable to read input file %s: %v", inputFile, err)
		}
		scenario, err := parser.Parse(rawScenario, m.SSHConfig.SSHHost, m.SSHConfig.SSHUsername, m.SSHConfig.SSHKey)
		if err != nil {
			return fmt.Errorf("unable to parse input file %s: %v", inputFile, err)
		}
		allScenarios = append(allScenarios, scenario...)
	}

	var hasError = false
	results := m.runScenariosParallel(allScenarios, func(result *ScenarioRunResult) {
		roundedDuration := math.Round(result.DurationSeconds*100) / 100
		if result.Success {
			log.Infof("Scenario '%s' passed in %.2f seconds", result.Description, roundedDuration)
		} else {
			hasError = true
			log.Errorf("Scenario '%s' failed in %.2f seconds: %s", result.Description, roundedDuration, result.ErrorMessage)
		}
	})

	// Handle output file
	if m.JsonOutputFile != "" {
		if err := m.writeJsonOutput(results); err != nil {
			return err
		}
		log.Infof("Wrote scenario test results to %s", m.JsonOutputFile)
	}

	// Return an error to exit with a non-zero status code if at least one test failed
	if hasError {
		return fmt.Errorf("at least 1 scenario failed")
	} else {
		return nil
	}
}

func (m *RunCommand) Validate() error {
	if len(m.InputFiles) == 0 {
		return errors.New("please provide at least 1 scenario")
	}

	// If an SSH key is provided, check it exists
	if sshKey := m.SSHConfig.SSHKey; sshKey != "" {
		if _, err := os.Stat(sshKey); err != nil && sshKey != "" {
			return fmt.Errorf("invalid SSH key file %s: %v", sshKey, err)
		}
	}

	return nil
}

// runScenariosParallel runs all the provided scenarios in parallel, honoring the maximum parallelism
// every time a test completes, the callback function is invoked
func (m *RunCommand) runScenariosParallel(allScenarios []*threatest.Scenario, callback func(result *ScenarioRunResult)) []ScenarioRunResult {
	numWorkers := m.Parallelism
	// No point in having more workers than scenarios to run
	if numScenarios := len(allScenarios); numScenarios < numWorkers {
		numWorkers = numScenarios
	}

	log.Infof("Running %d scenarios with a parallelism of %d", len(allScenarios), numWorkers)

	// Channel to hold "tasks" (scenarios to run)
	scenarioChan := make(chan *threatest.Scenario, numWorkers)
	// Channel to hold test results
	resultsChan := make(chan *ScenarioRunResult)

	// Create 1 worker by desired parallelism unit
	for worker := 0; worker < numWorkers; worker++ {
		go m.runSingleScenario(scenarioChan, resultsChan)
	}

	// Submit each scenario
	for _, scenario := range allScenarios {
		scenarioChan <- scenario
	}

	// Retrieve results as they are produced
	var allResults []ScenarioRunResult
	for range allScenarios {
		result := <-resultsChan
		callback(result)
		allResults = append(allResults, *result)
	}

	return allResults
}

// runSingleScenario runs inside a goroutine and uses Threatest to run one scenario
func (m *RunCommand) runSingleScenario(scenarios <-chan *threatest.Scenario, results chan<- *ScenarioRunResult) {
	for scenario := range scenarios {
		runner := threatest.Threatest()
		runner.Scenarios = append(runner.Scenarios, scenario)
		runner.Interval = 2 * time.Second

		start := time.Now()
		err := runner.Run()
		end := time.Now()

		var errorMessage = ""
		if err != nil {
			errorMessage = err.Error()
		}

		results <- &ScenarioRunResult{
			Description:     scenario.Name,
			ErrorMessage:    errorMessage,
			Success:         err == nil,
			DurationSeconds: end.Sub(start).Seconds(),
			TimeDetonated:   start,
		}
	}
}

func (m *RunCommand) writeJsonOutput(results []ScenarioRunResult) error {
	outputBytes, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("unable to convert scenario test results to JSON: %w", err)
	}

	if err := os.WriteFile(m.JsonOutputFile, outputBytes, 0600); err != nil {
		return fmt.Errorf("unable to write scenario test results to %s: %v", m.JsonOutputFile, err)
	}

	return nil
}
