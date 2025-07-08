package splunk

import (
	"github.com/datadog/threatest/pkg/threatest/matchers/splunk/api"
)

// SplunkNotable represents a Splunk notable event returned from a search
type SplunkNotable struct {
	ID        string // Notable UID
	Name      string
	Severity  string
	Timestamp string
	Custom    map[string]interface{}
}

// SplunkNotableGeneratedAssertion is a matcher for Splunk notable events
type SplunkNotableGeneratedAssertion struct {
	SplunkAPI     api.SplunkAPI
	NotableFilter SplunkNotableFilter
}

// SplunkNotableFilter defines search criteria for Splunk alerts
type SplunkNotableFilter struct {
	RuleName     string
	Severity     string
	StartTime    string
	EndTime      string
	DetectionUID string
}

// SplunkNotableGeneratedAssertionBuilder is a builder for SplunkNotableGeneratedAssertion
type SplunkNotableGeneratedAssertionBuilder struct {
	SplunkNotableGeneratedAssertion
}

// WithSeverity sets the severity for the Splunk notable event search.
func (m *SplunkNotableGeneratedAssertionBuilder) WithSeverity(severity string) *SplunkNotableGeneratedAssertionBuilder {
	m.NotableFilter.Severity = severity
	return m
}

// WithStartTime sets the start time for the Splunk notable event search.
// This is important to reduce the load on the search head when searching for notables.
func (m *SplunkNotableGeneratedAssertionBuilder) WithStartTime(startTime string) *SplunkNotableGeneratedAssertionBuilder {
	m.NotableFilter.StartTime = startTime
	return m
}

// WithEndTime sets the end time for the Splunk notable event search.
func (m *SplunkNotableGeneratedAssertionBuilder) WithEndTime(endTime string) *SplunkNotableGeneratedAssertionBuilder {
	m.NotableFilter.EndTime = endTime
	return m
}
