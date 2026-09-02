package parser

import (
	"fmt"
	"github.com/datadog/threatest/pkg/threatest"
	"github.com/datadog/threatest/pkg/threatest/detonators"
	"github.com/datadog/threatest/pkg/threatest/matchers"
	"github.com/datadog/threatest/pkg/threatest/matchers/datadog/agentevents"
	"github.com/datadog/threatest/pkg/threatest/matchers/datadog/logs"
	"github.com/datadog/threatest/pkg/threatest/matchers/datadog/signals"
	"github.com/datadog/threatest/pkg/threatest/matchers/elastic"
	"sigs.k8s.io/yaml" // we use this library as it provides a handy "YAMLToJSON" function
	"strings"
	"time"
)

// Parse turns a YAML input string into a list of Threatest scenarios
// TODO: A SSH configuration shouldn't be required at this point
func Parse(yamlInput []byte, sshHostname string, sshUsername string, sshKey string) ([]*threatest.Scenario, error) {
	jsonInput, err := yaml.YAMLToJSON(yamlInput)
	if err != nil {
		return nil, fmt.Errorf("unable to convert input YAML to JSON: %v", err)
	}

	parsed := ThreatestSchemaJson{}
	if err := parsed.UnmarshalJSON(jsonInput); err != nil {
		return nil, fmt.Errorf("unable to parse input: %v", err)
	}

	return buildScenarios(&parsed, sshHostname, sshUsername, sshKey)
}

func buildScenarios(parsed *ThreatestSchemaJson, sshHostname string, sshUsername string, sshKey string) ([]*threatest.Scenario, error) {
	scenarios := []*threatest.Scenario{}
	if len(parsed.Scenarios) == 0 {
		return nil, fmt.Errorf("input file has no scenarios defined")
	}

	for _, parsedScenario := range parsed.Scenarios {
		scenario := threatest.Scenario{}
		scenario.Name = parsedScenario.Name

		if !hasDetonation(parsedScenario) {
			return nil, fmt.Errorf("scenario '%s' has no detonation defined", parsedScenario.Name)
		}

		// Detonation
		if localDetonator := parsedScenario.Detonate.LocalDetonator; localDetonator != nil {
			commandToRun := strings.Join(parsedScenario.Detonate.LocalDetonator.Commands, "; ")
			scenario.Detonator = detonators.NewCommandDetonator(&detonators.LocalCommandExecutor{}, commandToRun)
		} else if remoteDetonator := parsedScenario.Detonate.RemoteDetonator; remoteDetonator != nil {
			commandToRun := strings.Join(remoteDetonator.Commands, "; ")
			//TODO: decouple
			//TODO: confirm 1 SSH executor per attack makes sense
			sshExecutor, err := detonators.NewSSHCommandExecutor(sshHostname, sshUsername, sshKey)
			if err != nil {
				return nil, fmt.Errorf("invalid SSH detonator configuration: %v", err)
			}
			scenario.Detonator = detonators.NewCommandDetonator(sshExecutor, commandToRun)
		} else if stratusRedTeamDetonator := parsedScenario.Detonate.StratusRedTeamDetonator; stratusRedTeamDetonator != nil {
			if stratusRedTeamDetonator.AttackTechnique == nil {
				return nil, fmt.Errorf("scenario '%s' has a Stratus Red Team detonator with no attackTechnique defined", parsedScenario.Name)
			}
			scenario.Detonator = detonators.StratusRedTeamTechnique(*stratusRedTeamDetonator.AttackTechnique)
		} else if awsCliDetonator := parsedScenario.Detonate.AwsCliDetonator; awsCliDetonator != nil {
			if awsCliDetonator.Script == nil {
				return nil, fmt.Errorf("scenario '%s' has an AWS CLI detonator with no script defined", parsedScenario.Name)
			}
			scenario.Detonator = detonators.NewAWSCLIDetonator(*awsCliDetonator.Script)
		}

		if len(parsedScenario.Expectations) == 0 {
			return nil, fmt.Errorf("scenario '%s' has no assertions defined", parsedScenario.Name)
		}
		if err := buildAssertions(&parsedScenario, &scenario); err != nil {
			return nil, err
		}

		//TODO: in the threatest core, the timeout should be part of each assertion (not scenario level)
		// We should probably define a default timeout at the CLI level
		rawTimeout := parsedScenario.Expectations[0].Timeout
		parsedDuration, err := time.ParseDuration(rawTimeout)
		if err != nil {
			return nil, fmt.Errorf("scenario '%s' has an invalid timeout '%s': '%v'", parsedScenario.Name, rawTimeout, err)
		}
		scenario.Timeout = parsedDuration

		scenarios = append(scenarios, &scenario)
	}
	return scenarios, nil
}

// hasDetonation returns true if the scenario has at least 1 detonation defined
func hasDetonation(scenario ThreatestSchemaJsonScenariosElem) bool {
	detonations := scenario.Detonate
	return detonations.LocalDetonator != nil ||
		detonations.RemoteDetonator != nil ||
		detonations.StratusRedTeamDetonator != nil ||
		detonations.AwsCliDetonator != nil
}

func buildAssertions(parsedScenario *ThreatestSchemaJsonScenariosElem, scenario *threatest.Scenario) error {
	for _, parsedAssertion := range parsedScenario.Expectations {
		if datadogMatcher := parsedAssertion.DatadogSecuritySignal; datadogMatcher != nil {
			if datadogMatcher.Query != nil && !parsedAssertion.Discover {
				return fmt.Errorf("scenario '%s': query on datadogSecuritySignal is only supported with discover: true", parsedScenario.Name)
			}
			if (datadogMatcher.Name == nil || *datadogMatcher.Name == "") && !parsedAssertion.Discover {
				return fmt.Errorf("scenario '%s': datadogSecuritySignal.name is required when discover is false", parsedScenario.Name)
			}
			var opts []signals.Option
			if severity := datadogMatcher.Severity; severity != nil {
				opts = append(opts, signals.WithSeverity(*severity))
			}
			name := derefStr(datadogMatcher.Name)
			addAssertion(scenario, signals.DatadogSecuritySignal(name, opts...), parsedAssertion, derefStr(datadogMatcher.Query))
		}
		if elasticMatcher := parsedAssertion.ElasticSecuritySignal; elasticMatcher != nil {
			if parsedAssertion.Discover {
				return fmt.Errorf("scenario '%s': discover mode is not supported for Elastic Security alerts", parsedScenario.Name)
			}
			var opts []elastic.Option
			if severity := elasticMatcher.Severity; severity != nil {
				opts = append(opts, elastic.WithSeverity(*severity))
			}
			addAssertion(scenario, elastic.ElasticSecurityAlert(elasticMatcher.Name, opts...), parsedAssertion, "")
		}
		if datadogLogMatcher := parsedAssertion.DatadogLog; datadogLogMatcher != nil {
			var opts []logs.Option
			if datadogLogMatcher.Query != nil {
				opts = append(opts, logs.WithQuery(*datadogLogMatcher.Query))
			}
			addAssertion(scenario, logs.DatadogLog(opts...), parsedAssertion, derefStr(datadogLogMatcher.Query))
		}
		if datadogEventMatcher := parsedAssertion.DatadogEvent; datadogEventMatcher != nil {
			var opts []agentevents.Option
			if datadogEventMatcher.Query != nil {
				opts = append(opts, agentevents.WithQuery(*datadogEventMatcher.Query))
			}
			addAssertion(scenario, agentevents.DatadogAgentEvent(opts...), parsedAssertion, derefStr(datadogEventMatcher.Query))
		}
	}
	return nil
}

func addAssertion(scenario *threatest.Scenario, matcher matchers.TelemetryMatcher, parsedAssertion ThreatestSchemaJsonScenariosElemExpectationsElem, query string) {
	scenario.TelemetryAssertions = append(scenario.TelemetryAssertions, threatest.TelemetryAssertion{
		Matcher:  matcher,
		Discover: parsedAssertion.Discover,
		Query:    query,
	})
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
