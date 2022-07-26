package examples

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	. "github.com/datadog/threatest/pkg/threatest"
	. "github.com/datadog/threatest/pkg/threatest/detonators"
	"github.com/datadog/threatest/pkg/threatest/matchers/datadog"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCustomAWSDetonator(t *testing.T) {
	threatest := Threatest()
	threatest.Scenario("create admin IAM user").
		WhenDetonating(NewAWSDetonator(func(awsConfig aws.Config, detonationUuid uuid.UUID) error {
			iamClient := iam.NewFromConfig(awsConfig)
			username := aws.String("my-user-foo")
			policy := aws.String("arn:aws:iam::aws:policy/AdministratorAccess")

			// create an IAM user
			_, err := iamClient.CreateUser(context.Background(), &iam.CreateUserInput{UserName: username})
			assert.Nil(t, err)

			// assign it an administrator policy
			_, err = iamClient.AttachUserPolicy(context.Background(), &iam.AttachUserPolicyInput{PolicyArn: policy, UserName: username})
			assert.Nil(t, err)

			// cleanup
			_, err = iamClient.DetachUserPolicy(context.Background(), &iam.DetachUserPolicyInput{UserName: username, PolicyArn: policy})
			assert.Nil(t, err)
			_, err = iamClient.DeleteUser(context.Background(), &iam.DeleteUserInput{UserName: username})
			assert.Nil(t, err)

			return nil
		})).
		Expect(datadog.DatadogSecuritySignal("AWS IAM privileged policy was applied to a user")).
		WithTimeout(15 * time.Minute)

	assert.Nil(t, threatest.Run())
}
