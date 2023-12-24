package atomic

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
)

func TestInterpolateCommand(t *testing.T) {
	testCases := map[string]struct {
		test           *Test
		arguments      map[string]string
		expectedOutput string
	}{
		"no templating and no arguments": {
			test: &Test{
				Executor:       Executor{Command: aws.String("echo 'Hello World!'")},
				InputArguments: nil,
			},
			arguments:      nil,
			expectedOutput: "echo 'Hello World!'",
		},
		"no templating and some arguments": {
			test: &Test{
				Executor:       Executor{Command: aws.String("echo 'Hello World!'")},
				InputArguments: map[string]InputArgument{"first_name": {}, "last_name": {}},
			},
			arguments:      map[string]string{"first_name": "John", "last_name": "Doe"},
			expectedOutput: "echo 'Hello World!'",
		},
		"templating and no arguments": {
			test: &Test{
				Executor:       Executor{Command: aws.String("echo 'Hello ${first_name} ${last_name}!'")},
				InputArguments: map[string]InputArgument{"first_name": {}, "last_name": {}},
			},
			arguments:      nil,
			expectedOutput: "echo 'Hello  !'",
		},
		"templating and some arguments": {
			test: &Test{
				Executor:       Executor{Command: aws.String("echo 'Hello ${first_name} ${last_name}!'")},
				InputArguments: map[string]InputArgument{"first_name": {}, "last_name": {}},
			},
			arguments:      map[string]string{"first_name": "John"},
			expectedOutput: "echo 'Hello John !'",
		},
		"templating and all arguments": {
			test: &Test{
				Executor:       Executor{Command: aws.String("echo 'Hello ${first_name} ${last_name}!'")},
				InputArguments: map[string]InputArgument{"first_name": {}, "last_name": {}},
			},
			arguments:      map[string]string{"first_name": "John", "last_name": "Doe"},
			expectedOutput: "echo 'Hello John Doe!'",
		},
	}

	for testCaseName, testCaseData := range testCases {
		t.Run(testCaseName, func(t *testing.T) {
			assert.Equal(t, testCaseData.expectedOutput, testCaseData.test.interpolateCommand(*testCaseData.test.Executor.Command, testCaseData.arguments))
		})
	}
}
