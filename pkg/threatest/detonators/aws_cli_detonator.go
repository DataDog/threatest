package detonators

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/google/uuid"
	"os"
	"os/exec"
)

/*
AWSCLIDetonator allows to execute arbitrary AWS CLI commands, pre-configured to inject the detonation UUID
in the user-agent.
*/
type AWSCLIDetonator struct {
	Script string
}

func NewAWSCLIDetonator(script string) *AWSCLIDetonator {
	return &AWSCLIDetonator{Script: script}
}

func (m *AWSCLIDetonator) Detonate() (string, error) {
	detonationUuid := uuid.New()

	// Sanity check: are we authenticated to AWS?
	awsConfig, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return "", fmt.Errorf("unable to load AWS configuration: %v", err)
	}
	_, err = awsConfig.Credentials.Retrieve(context.Background())
	if err != nil {
		return "", fmt.Errorf("you are not authenticated to AWS")
	}

	cmd := exec.Command("bash", "-c", m.Script)
	cmd.Env = os.Environ() // inherit environment
	cmd.Env = append(cmd.Env, "AWS_EXECUTION_ENV=threatest_"+detonationUuid.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("AWS CLI script failed. Output shown below:\n%s", output)
	}

	fmt.Println("Execution ID: " + detonationUuid.String())

	return detonationUuid.String(), nil
}
