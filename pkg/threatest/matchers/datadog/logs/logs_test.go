package logs

import (
	"testing"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/aws/smithy-go/ptr"
	"github.com/stretchr/testify/assert"
)

func sampleLog(id, message, service, status string) datadogV2.Log {
	l := datadogV2.NewLog()
	l.Id = ptr.String(id)
	l.Attributes = &datadogV2.LogAttributes{
		Message:    ptr.String(message),
		Service:    ptr.String(service),
		Status:     ptr.String(status),
		Host:       ptr.String("host-" + id),
		Timestamp:  ptr.Time(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
		Attributes: map[string]interface{}{"custom": "val-" + id},
	}
	return *l
}

func TestConvertLog(t *testing.T) {
	result := convertLog(sampleLog("log-1", "hello", "aws", "info"))
	assert.Equal(t, "hello", result.Attributes["message"])
	assert.Equal(t, "aws", result.Attributes["service"])
	assert.Equal(t, "info", result.Attributes["status"])
	assert.Equal(t, "host-log-1", result.Attributes["host"])
	assert.Equal(t, "val-log-1", result.Attributes["custom"])
	assert.NotNil(t, result.Body)
}

func TestConvertLogNilFields(t *testing.T) {
	l := datadogV2.NewLog()
	l.Id = ptr.String("log-1")
	result := convertLog(*l)
	assert.Equal(t, "log-1", result.Attributes["id"])
}

func TestRelatedLogsDefaultQuery(t *testing.T) {
	m := &Matcher{Filter: &Filter{}}
	assert.Equal(t, "*:*my-uuid*", m.defaultCorrelationQuery("my-uuid"))
}

func TestRelatedLogsCustomQuery(t *testing.T) {
	m := &Matcher{Filter: &Filter{Query: "service:aws"}}
	assert.Equal(t, "service:aws", m.defaultCorrelationQuery("my-uuid"))
}
