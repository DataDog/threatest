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

// DatadogAlertGeneratedAssertionBuilder constructs a DatadogAlertGeneratedAssertion
// using the builder pattern.
type DatadogAlertGeneratedAssertionBuilder struct {
	DatadogAlertGeneratedAssertion
}

// Option configures a DatadogAlertGeneratedAssertionBuilder.
type Option func(*DatadogAlertGeneratedAssertionBuilder)

// WithCredentials overrides the default environment-variable-based
// credentials (DD_API_KEY, DD_APP_KEY, DD_SITE) with explicit values.
// This is useful when querying signals across multiple Datadog orgs.
func WithCredentials(apiKey, appKey, site string) Option {
	return func(b *DatadogAlertGeneratedAssertionBuilder) {
		b.SignalsAPI = newSignalsAPI(apiKey, appKey, site)
	}
}

// WithSeverity filters signals by severity (e.g. "medium", "high").
func WithSeverity(severity string) Option {
	return func(b *DatadogAlertGeneratedAssertionBuilder) {
		b.AlertFilter.Severity = severity
	}
}

func GetDDSite() string {
	if ddSite, isSet := os.LookupEnv("DD_SITE"); isSet {
		return ddSite
	}
	return "datadoghq.com"
}

// newSignalsAPI creates a DatadogSecuritySignalsAPI with explicit credentials.
func newSignalsAPI(apiKey, appKey, site string) DatadogSecuritySignalsAPI {
	ctx := context.WithValue(context.Background(), datadog.ContextAPIKeys, map[string]datadog.APIKey{
		"apiKeyAuth": {Key: apiKey},
		"appKeyAuth": {Key: appKey},
	})
	ctx = context.WithValue(ctx, datadog.ContextServerVariables, map[string]string{
		"site": site,
	})
	cfg := datadog.NewConfiguration()
	cfg.SetUnstableOperationEnabled("SearchSecurityMonitoringSignals", true)

	return &DatadogSecuritySignalsAPIImpl{
		securityMonitoringAPI: datadogV2.NewSecurityMonitoringApi(datadog.NewAPIClient(cfg)),
		ctx:                   ctx,
	}
}

// DatadogSecuritySignal creates a builder for matching Datadog security
// signals by rule name. By default, credentials are read from DD_API_KEY,
// DD_APP_KEY, and DD_SITE environment variables. Use WithCredentials to
// override.
func DatadogSecuritySignal(name string, opts ...Option) *DatadogAlertGeneratedAssertionBuilder {
	builder := &DatadogAlertGeneratedAssertionBuilder{}
	builder.SignalsAPI = newSignalsAPI(
		os.Getenv("DD_API_KEY"),
		os.Getenv("DD_APP_KEY"),
		GetDDSite(),
	)
	builder.AlertFilter = &DatadogAlertFilter{RuleName: name}

	for _, opt := range opts {
		opt(builder)
	}

	return builder
}

// Deprecated: Use WithSeverity option instead.
func (m *DatadogAlertGeneratedAssertionBuilder) WithSeverity(severity string) *DatadogAlertGeneratedAssertionBuilder {
	m.AlertFilter.Severity = severity
	return m
}
