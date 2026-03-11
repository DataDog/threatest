package datadog

import (
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

type DiscoveredSignal struct {
	SignalID  string
	RuleName  string
	Severity  string
	Message   string
	Timestamp time.Time
	Tags      []string
}

func DiscoverSignals(api DatadogSecuritySignalsAPI, detonationUid string) ([]DiscoveredSignal, error) {
	query := fmt.Sprintf(QueryOpenSignalsFreeText, detonationUid)
	signals, err := api.SearchSignals(query)
	if err != nil {
		log.Warnf("Error querying signals (returning partial results): %v", err)
		return nil, err
	}

	var discovered []DiscoveredSignal
	for _, signal := range signals {
		ds := DiscoveredSignal{}

		if signal.Id != nil {
			ds.SignalID = *signal.Id
		}

		if signal.Attributes == nil {
			continue
		}

		if signal.Attributes.Message != nil {
			ds.Message = *signal.Attributes.Message
		}

		if signal.Attributes.Timestamp != nil {
			ds.Timestamp = *signal.Attributes.Timestamp
		}

		if signal.Attributes.Tags != nil {
			ds.Tags = signal.Attributes.Tags
		}

		ds.RuleName = extractRuleName(signal.Attributes.Custom)
		ds.Severity = extractSeverity(signal.Attributes.Tags)

		discovered = append(discovered, ds)
	}

	return discovered, nil
}

func extractRuleName(custom map[string]interface{}) string {
	workflow, ok := custom["workflow"].(map[string]interface{})
	if !ok {
		return ""
	}
	rule, ok := workflow["rule"].(map[string]interface{})
	if !ok {
		return ""
	}
	name, ok := rule["name"].(string)
	if !ok {
		return ""
	}
	return name
}

func extractSeverity(tags []string) string {
	for _, tag := range tags {
		if strings.HasPrefix(tag, "status:") {
			return strings.TrimPrefix(tag, "status:")
		}
	}
	return ""
}
