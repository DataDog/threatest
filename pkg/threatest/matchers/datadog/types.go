package datadog

import (
	"context"
	"github.com/DataDog/datadog-api-client-go/api/v2/datadog"
	"os"
)

type DatadogAlertFilter struct {
	RuleName string `yaml:"rule-name"`
	Severity string
	// There might be other attributes in the future
}

type DatadogAlertGeneratedAssertion struct {
	SignalsAPI  DatadogSecuritySignalsAPI
	AlertFilter *DatadogAlertFilter
}

// builder
type DatadogAlertGeneratedAssertionBuilder struct {
	DatadogAlertGeneratedAssertion
}

func DatadogSecuritySignal(name string) *DatadogAlertGeneratedAssertionBuilder {
	builder := &DatadogAlertGeneratedAssertionBuilder{}
	ddApiKey := os.Getenv("DD_API_KEY")
	ddAppKey := os.Getenv("DD_APP_KEY")
	ctx := context.WithValue(context.Background(), datadog.ContextAPIKeys, map[string]datadog.APIKey{
		"apiKeyAuth": {Key: ddApiKey},
		"appKeyAuth": {Key: ddAppKey},
	})
	cfg := datadog.NewConfiguration()
	cfg.SetUnstableOperationEnabled("SearchSecurityMonitoringSignals", true)

	builder.SignalsAPI = &DatadogSecuritySignalsAPIImpl{
		apiClient: datadog.NewAPIClient(cfg),
		ctx:       ctx,
	}
	builder.AlertFilter = &DatadogAlertFilter{RuleName: name}
	return builder
}

func (m *DatadogAlertGeneratedAssertionBuilder) WithSeverity(severity string) *DatadogAlertGeneratedAssertionBuilder {
	m.AlertFilter.Severity = severity
	return m
}
