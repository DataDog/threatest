package examples

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	. "github.com/datadog/threatest/pkg/threatest"
	. "github.com/datadog/threatest/pkg/threatest/detonators"
	. "github.com/datadog/threatest/pkg/threatest/matchers/datadog"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"time"

	"github.com/gruntwork-io/terratest/modules/terraform"
	"testing"
)

func TestCustomAWSDetonatorWithTerratest(t *testing.T) {
	// Step 1: Use terratest to spin up our pre-requisite infrastructure
	terraformOptions := terraform.WithDefaultRetryableErrors(t, &terraform.Options{
		TerraformDir: "./terraform",
	})
	defer terraform.Destroy(t, terraformOptions)
	terraform.InitAndApply(t, terraformOptions)
	trailName := terraform.Output(t, terraformOptions, "cloudtrail_trail_name")

	// Step 2: Test scenario
	threatest := Threatest()

	threatest.Scenario("stopping cloudtrail trail").
		WhenDetonating(NewAWSDetonator(func(config aws.Config, _ uuid.UUID) error {
			// Threatest automatically injects the detonation UUID inside the AWS SDK user-agent
			// allowing to correlate the alert with the detonation
			cloudtrailClient := cloudtrail.NewFromConfig(config)
			cloudtrailClient.UpdateTrail(context.Background(), &cloudtrail.UpdateTrailInput{
				Name:         aws.String(trailName),
				S3BucketName: aws.String("nope"),
			})
			return nil
		})).
		Expect(DatadogSecuritySignal("AWS CloudTrail configuration modified")).
		WithTimeout(15 * time.Minute)

	assert.NoError(t, threatest.Run())
}
