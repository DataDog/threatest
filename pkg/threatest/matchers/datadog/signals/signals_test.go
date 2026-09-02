package signals

import (
	"strconv"
	"testing"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/aws/smithy-go/ptr"
	"github.com/stretchr/testify/assert"
)

func sampleSignal(id int) *datadogV2.SecurityMonitoringSignal {
	s := datadogV2.NewSecurityMonitoringSignal()
	s.Id = ptr.String(strconv.Itoa(id))
	s.Attributes = &datadogV2.SecurityMonitoringSignalAttributes{Custom: map[string]interface{}{}}
	return s
}

func TestConvertSignal(t *testing.T) {
	s := sampleSignal(1)
	s.Attributes.Custom["@workflow.rule.name"] = "AWS IAM backdoor"
	s.Attributes.Custom["status"] = "high"
	s.Attributes.Custom["foobar"] = "my-uuid"
	s.Attributes.Tags = []string{"env:sandbox"}

	result := convertSignal(*s)
	assert.Equal(t, "signal", result.EventName)
	assert.Equal(t, "1", result.Attributes["id"])
	assert.Equal(t, "AWS IAM backdoor", result.Attributes["@workflow.rule.name"])
	assert.Equal(t, "high", result.Attributes["status"])
	assert.Equal(t, "my-uuid", result.Attributes["foobar"])
	assert.NotNil(t, result.Body)
}

func TestConvertSignalNilAttributes(t *testing.T) {
	s := datadogV2.NewSecurityMonitoringSignal()
	s.Id = ptr.String("sig-1")
	s.Attributes = nil

	result := convertSignal(*s)
	assert.Equal(t, "sig-1", result.Attributes["id"])
}

func TestConvertSignalAdditionalProperties(t *testing.T) {
	s := datadogV2.NewSecurityMonitoringSignal()
	s.Id = ptr.String("sig-1")
	s.Attributes = &datadogV2.SecurityMonitoringSignalAttributes{
		AdditionalProperties: map[string]interface{}{
			"attributes": map[string]interface{}{"foobar": "uid-from-ap"},
		},
	}

	result := convertSignal(*s)
	assert.Equal(t, "uid-from-ap", result.Attributes["foobar"])
}

func TestSignalMatchesExecution(t *testing.T) {
	m := &Matcher{Filter: &Filter{RuleName: "test"}}
	uid := "my-uuid"

	matching := *sampleSignal(1)
	matching.Attributes.Custom["foobar"] = uid

	nonMatching := *sampleSignal(2)

	assert.True(t, m.signalMatchesExecution(matching, uid))
	assert.False(t, m.signalMatchesExecution(nonMatching, uid))
}

func TestSignalMatchesExecutionAdditionalProperties(t *testing.T) {
	m := &Matcher{Filter: &Filter{RuleName: "test"}}
	uid := "my-uuid"

	s := datadogV2.NewSecurityMonitoringSignal()
	s.Attributes = &datadogV2.SecurityMonitoringSignalAttributes{
		AdditionalProperties: map[string]interface{}{
			"attributes": map[string]interface{}{"foobar": uid},
		},
	}

	assert.True(t, m.signalMatchesExecution(*s, uid))
}
