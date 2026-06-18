package elastic

import (
	"net/http"
	"os"

	"github.com/datadog/threatest/pkg/threatest/secret"
)

// ElasticSecurityAlertFilter holds filtering criteria for Elastic Security alerts.
type ElasticSecurityAlertFilter struct {
	RuleName string `yaml:"rule-name"`
	Severity string
	// There might be other attributes in the future
}

// ElasticSecurityAlertGeneratedAssertion verifies that an expected Elastic
// Security detection alert was generated.
type ElasticSecurityAlertGeneratedAssertion struct {
	AlertsAPI   ElasticSecurityDetectionAlertsAPI
	AlertFilter *ElasticSecurityAlertFilter
}

// ElasticSecurityAlertGeneratedAssertionBuilder constructs an
// ElasticSecurityAlertGeneratedAssertion using the builder pattern.
type ElasticSecurityAlertGeneratedAssertionBuilder struct {
	ElasticSecurityAlertGeneratedAssertion
}

// Option configures an ElasticSecurityAlertGeneratedAssertionBuilder.
type Option func(*ElasticSecurityAlertGeneratedAssertionBuilder)

// WithCredentials overrides the default environment-variable-based
// credentials (KIBANA_URL, ELASTIC_API_KEY) with explicit values.
// This is useful when querying alerts across multiple Elastic deployments.
func WithCredentials(kibanaURL, apiKey string) Option {
	return func(b *ElasticSecurityAlertGeneratedAssertionBuilder) {
		b.AlertsAPI = newAlertsAPI(kibanaURL, apiKey)
	}
}

// WithSeverity filters alerts by severity (e.g. "medium", "high").
func WithSeverity(severity string) Option {
	return func(b *ElasticSecurityAlertGeneratedAssertionBuilder) {
		b.AlertFilter.Severity = severity
	}
}

// newAlertsAPI creates an ElasticSecurityDetectionAlertsAPI with explicit credentials.
func newAlertsAPI(kibanaURL, apiKey string) ElasticSecurityDetectionAlertsAPI {
	return &ElasticSecurityDetectionAlertsAPIImpl{
		kibanaURL: kibanaURL,
		apiKey:    secret.New(apiKey),
		client:    &http.Client{Timeout: requestTimeout},
	}
}

// ElasticSecurityAlert creates a builder for matching Elastic Security
// detection alerts by rule name. By default, credentials are read from
// the KIBANA_URL and ELASTIC_API_KEY environment variables. 
func ElasticSecurityAlert(name string, opts ...Option) *ElasticSecurityAlertGeneratedAssertionBuilder {
	builder := &ElasticSecurityAlertGeneratedAssertionBuilder{}
	builder.AlertsAPI = newAlertsAPI(
		os.Getenv("KIBANA_URL"),
		os.Getenv("ELASTIC_API_KEY"),
	)
	builder.AlertFilter = &ElasticSecurityAlertFilter{RuleName: name}

	for _, opt := range opts {
		opt(builder)
	}

	return builder
}
