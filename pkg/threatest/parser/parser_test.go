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
`
	scenarios, err := Parse([]byte(validYaml), "", "", "")
	assert.Nil(t, err, "parsing a valid YAML scenario file should not return an error")
	assert.Len(t, scenarios, 2)

	assert.Equal(t, scenarios[0].Name, "curl metadata service")
	assert.NotNil(t, scenarios[0].Detonator)
	assert.Len(t, scenarios[0].Assertions, 1)

	assert.Equal(t, scenarios[1].Name, "opening a security group to the Internet")
	assert.NotNil(t, scenarios[1].Detonator)
	assert.Len(t, scenarios[1].Assertions, 1)
}
