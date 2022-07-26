package detonators

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/google/uuid"
)

/*
	The AWS Detonator allows to send arbitrary requests using the AWS SDK, pre-configured to inject the detonation UUID
	in the user-agent.
*/
type AWSDetonator struct {
	DetonationFunc func(awsConfig aws.Config, detonationUuid uuid.UUID) error
}

func NewAWSDetonator(DetonationFunc func(aws.Config, uuid.UUID) error) *AWSDetonator {
	return &AWSDetonator{DetonationFunc: DetonationFunc}
}

func (m *AWSDetonator) Detonate() (string, error) {
	detonationUuid := uuid.New()
	awsConfig, err := config.LoadDefaultConfig(context.Background(), customUserAgentApiOptions(detonationUuid))
	if err != nil {
		return "", fmt.Errorf("unable to authenticate to AWS: %v", err)
	}

	if err := m.DetonationFunc(awsConfig, detonationUuid); err != nil {
		return "", err
	}

	return detonationUuid.String(), nil
}

// Functions below are related to customization of the user-agent header
// Code mostly taken from https://github.com/aws/aws-sdk-go-v2/issues/1432

func customUserAgentApiOptions(uniqueCorrelationId uuid.UUID) config.LoadOptionsFunc {
	return config.WithAPIOptions(func() (v []func(stack *middleware.Stack) error) {
		v = append(v, func(stack *middleware.Stack) error {
			return stack.Build.Add(customUserAgentMiddleware(uniqueCorrelationId), middleware.After)
		})
		return v
	}())
}

func customUserAgentMiddleware(uniqueId uuid.UUID) middleware.BuildMiddleware {
	return middleware.BuildMiddlewareFunc("CustomerUserAgent", func(
		ctx context.Context, input middleware.BuildInput, next middleware.BuildHandler,
	) (out middleware.BuildOutput, metadata middleware.Metadata, err error) {
		request, ok := input.Request.(*smithyhttp.Request)
		if !ok {
			return out, metadata, fmt.Errorf("unknown transport type %T", input.Request)
		}
		request.Header.Set("User-Agent", fmt.Sprintf("threatest_"+uniqueId.String()))

		return next.HandleBuild(ctx, input)
	})
}
