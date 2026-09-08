package parser

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestParserRejectsDetonatorWithMissingRequiredField ensures the parser returns
// an error (instead of panicking with a nil pointer dereference) when a
// detonator block is present in the YAML but its required inner field is
// omitted.
func TestParserRejectsDetonatorWithMissingRequiredField(t *testing.T) {
	cases := []struct {
		name          string
		yamlInput     string
		expectedError string
	}{
		{
			name: "awsCliDetonator without script",
			yamlInput: `
scenarios:
  - name: A
    detonate:
      awsCliDetonator: {}
    expectations:
      - timeout: 1m
        datadogSecuritySignal:
          name: foo
`,
			expectedError: "scenario 'A' has an AWS CLI detonator with no script defined",
		},
		{
			name: "stratusRedTeamDetonator without attackTechnique",
			yamlInput: `
scenarios:
  - name: B
    detonate:
      stratusRedTeamDetonator: {}
    expectations:
      - timeout: 1m
        datadogSecuritySignal:
          name: foo
`,
			expectedError: "scenario 'B' has a Stratus Red Team detonator with no attackTechnique defined",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scenarios, err := Parse([]byte(tc.yamlInput), "", "", "")
			assert.Nil(t, scenarios)
			assert.EqualError(t, err, tc.expectedError)
		})
	}
}

func TestParserCorrectlyParsesValidInput(t *testing.T) {
	validYaml := `
scenarios:
  # Example 1: Remote detonation over SSH
  # Note: SSH configuration is provided using the --ssh-host, --ssh-username and --ssh-keyfile CLI arguments
  - name: curl metadata service
    detonate:
      remoteDetonator:
        commands: ["curl http://169.254.169.254 --connect-timeout 1"]
    expectations:
      - timeout: 1m
        datadogSecuritySignal:
          name: "Network utility accessed cloud metadata service"
          severity: medium

  # Example 2: Stratus Red Team detonation
  # Note: You must be authenticated to the relevant cloud provider before running it
  # The example below is equivalent to manually running "stratus detonate aws.exfiltration.ec2-security-group-open-port-22-ingress"
  - name: opening a security group to the Internet
    detonate:
      stratusRedTeamDetonator:
        attackTechnique: aws.exfiltration.ec2-security-group-open-port-22-ingress
    expectations:
      - timeout: 15m
        datadogSecuritySignal:
          name: "Potential administrative port open to the world via AWS security group"

  # Example 3: Elastic Security detection alert expectation
  - name: curl metadata service detected by Elastic
    detonate:
      remoteDetonator:
        commands: ["curl http://169.254.169.254 --connect-timeout 1"]
    expectations:
      - timeout: 1m
        elasticSecuritySignal:
          name: "Network utility accessed cloud metadata service"
          severity: medium
`
	scenarios, err := Parse([]byte(validYaml), "", "", "")
	assert.Nil(t, err, "parsing a valid YAML scenario file should not return an error")
	assert.Len(t, scenarios, 3)

	assert.Equal(t, scenarios[0].Name, "curl metadata service")
	assert.NotNil(t, scenarios[0].Detonator)
	assert.Len(t, scenarios[0].TelemetryAssertions, 1)

	assert.Equal(t, scenarios[1].Name, "opening a security group to the Internet")
	assert.NotNil(t, scenarios[1].Detonator)
	assert.Len(t, scenarios[1].TelemetryAssertions, 1)

	assert.Equal(t, scenarios[2].Name, "curl metadata service detected by Elastic")
	assert.NotNil(t, scenarios[2].Detonator)
	assert.Len(t, scenarios[2].TelemetryAssertions, 1)
	assert.Equal(t, "Elastic Security alert 'Network utility accessed cloud metadata service'", scenarios[2].TelemetryAssertions[0].Matcher.String())
}

func TestParserParsesNewTelemetryBlocksAndDiscoverFlag(t *testing.T) {
	yamlInput := `
scenarios:
  - name: discover logs and events
    detonate:
      localDetonator:
        commands: ["echo hi"]
    expectations:
      - timeout: 5m
        datadogLog:
          query: "<% .CorrelationID %>"
        discover: true
      - timeout: 5m
        datadogEvent:
          query: "stratus-red-team"
        discover: true
      - timeout: 5m
        datadogSecuritySignal:
          name: "some signal"
        discover: true
`
	scenarios, err := Parse([]byte(yamlInput), "", "", "")
	assert.Nil(t, err, "parsing new telemetry blocks should not error")
	assert.Len(t, scenarios, 1)
	assert.Equal(t, "discover logs and events", scenarios[0].Name)
	assert.NotNil(t, scenarios[0].Detonator)
	assert.Len(t, scenarios[0].TelemetryAssertions, 3)
	assert.True(t, scenarios[0].TelemetryAssertions[0].Discover)
	assert.Equal(t, "<% .CorrelationID %>", scenarios[0].TelemetryAssertions[0].Query)
	assert.True(t, scenarios[0].TelemetryAssertions[1].Discover)
	assert.Equal(t, "stratus-red-team", scenarios[0].TelemetryAssertions[1].Query)
	assert.True(t, scenarios[0].TelemetryAssertions[2].Discover)
}

func TestParserParsesDiscoverDefaultFalse(t *testing.T) {
	yamlInput := `
scenarios:
  - name: assert only
    detonate:
      localDetonator:
        commands: ["echo hi"]
    expectations:
      - timeout: 1m
        datadogSecuritySignal:
          name: foo
`
	scenarios, err := Parse([]byte(yamlInput), "", "", "")
	assert.Nil(t, err)
	assert.Len(t, scenarios, 1)
	assert.Len(t, scenarios[0].TelemetryAssertions, 1)
	assert.False(t, scenarios[0].TelemetryAssertions[0].Discover)
}

func TestParserRejectsElasticDiscover(t *testing.T) {
	yamlInput := `
scenarios:
  - name: elastic discover
    detonate:
      localDetonator:
        commands: ["echo hi"]
    expectations:
      - timeout: 1m
        elasticSecuritySignal:
          name: foo
        discover: true
`
	scenarios, err := Parse([]byte(yamlInput), "", "", "")
	assert.Nil(t, scenarios)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "discover mode is not supported for Elastic Security")
}

func TestParserRejectsAlertQueryWithoutDiscover(t *testing.T) {
	yamlInput := `
scenarios:
  - name: alert query without discover
    detonate:
      localDetonator:
        commands: ["echo hi"]
    expectations:
      - timeout: 1m
        datadogSecuritySignal:
          name: foo
          query: "service:aws"
`
	scenarios, err := Parse([]byte(yamlInput), "", "", "")
	assert.Nil(t, scenarios)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "query on datadogSecuritySignal is only supported with discover: true")
}

func TestParserRejectsMissingSignalName(t *testing.T) {
	yamlInput := `
scenarios:
  - name: missing name
    detonate:
      localDetonator:
        commands: ["echo hi"]
    expectations:
      - timeout: 1m
        datadogSecuritySignal: {}
`
	scenarios, err := Parse([]byte(yamlInput), "", "", "")
	assert.Nil(t, scenarios)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "datadogSecuritySignal.name is required when discover is false")
}
