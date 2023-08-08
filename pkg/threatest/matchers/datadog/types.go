package datadog

import (
	"context"
	"os"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
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

func GetDDSite() string {
	if ddSite, isSet := os.LookupEnv("DD_SITE"); isSet {
		return ddSite
	}
	return "datadoghq.com"
}

func DatadogSecuritySignal(name string) *DatadogAlertGeneratedAssertionBuilder {
	builder := &DatadogAlertGeneratedAssertionBuilder{}
	ddApiKey := os.Getenv("DD_API_KEY")
	ddAppKey := os.Getenv("DD_APP_KEY")
	ctx := context.WithValue(context.Background(), datadog.ContextAPIKeys, map[string]datadog.APIKey{
		"apiKeyAuth": {Key: ddApiKey},
		"appKeyAuth": {Key: ddAppKey},
	})
	ctx = context.WithValue(ctx, datadog.ContextServerVariables, map[string]string{
		"site": GetDDSite(),
	})
	cfg := datadog.NewConfiguration()
	cfg.SetUnstableOperationEnabled("SearchSecurityMonitoringSignals", true)

	builder.SignalsAPI = &DatadogSecuritySignalsAPIImpl{
		securityMonitoringAPI: datadogV2.NewSecurityMonitoringApi(datadog.NewAPIClient(cfg)),
		ctx:                   ctx,
	}
	builder.AlertFilter = &DatadogAlertFilter{RuleName: name}
	return builder
}

func (m *DatadogAlertGeneratedAssertionBuilder) WithSeverity(severity string) *DatadogAlertGeneratedAssertionBuilder {
	m.AlertFilter.Severity = severity
	return m
}
