package elasticsearch

import (
	"fmt"
	"strings"
	log "github.com/sirupsen/logrus"
	"encoding/json"
	"errors"
)

func FilterByUuidPresence(alerts []ElasticsearchQueryHit, uuid string) []ElasticsearchQueryHit {
	var filteredAlerts []ElasticsearchQueryHit
	var containsUuid bool
	for _,alert := range alerts {
		containsUuid = false
		for _,v := range alert.Source {
			if strings.Contains(v.(string), uuid) {
				containsUuid = true
				break
			}
		}
		if containsUuid {
			filteredAlerts = append(filteredAlerts, alert)
		}
	}
	return filteredAlerts
}

func StripHTTPStatusCode(response string) (string, error) {
    index := strings.Index(response, "{")
    if index != -1 {
        return response[index:], nil
    } else {
        return "", errors.New("No '{' found in Elasticsearch query response")
    }
}

func RetrieveAlerts(m *ElasticsearchAlertGeneratedAssertion, uuidField, ruleName string) ([]ElasticsearchQueryHit, error) {
	// The alias for the Elasticsearch index where alerts are stored
	const ALERT_INDEX string = ".siem-signals-default"
	// Construct the query necessary to find the alert
	query := `
	{
		"_source": [ "%s" ],
		"query": {
			"bool": { 
				"filter": [ 
					{ "range": { "@timestamp": { "gte": "now-3d" }}},
					{ "term":  { "kibana.alert.rule.name": "%s" }},
					{ "term":  { "kibana.alert.workflow_status": "open" }}
				]
			}
		}
	}`
	// Template in the field we expect to find the UUID in, and the rule we hope was triggered.
	query = fmt.Sprintf(query, uuidField, ruleName)
	// Query the Elasticsearch API
	res, err := m.AlertAPI.Search(
		m.AlertAPI.Search.WithIndex(ALERT_INDEX),
		m.AlertAPI.Search.WithBody(strings.NewReader(query)),
	)
	if err != nil {
		log.Fatal("Error while running Elasticsearch query")
		return nil, err
	}
	// Parse the response
	strippedResponse, err := StripHTTPStatusCode(res.String())
	if err != nil {
		log.Fatal("Error while stripping prepended HTTP status code")
		return nil, err
	}
	var data ElasticsearchQueryResponse
	if err := json.Unmarshal([]byte(strippedResponse), &data); err != nil {
		log.Fatal("Error unmarshalling JSON string into ElasticsearchQueryResponse struct")
		return nil, err
	}

	return data.Hits.Hits, nil
}

func (m *ElasticsearchAlertGeneratedAssertion) HasExpectedAlert(detonationUuid string) (bool, error) {
	log.Infof("Searching for open alerts for rule: %s with UUID: %s in field: %s", m.AlertFilter.RuleName, detonationUuid, m.AlertFilter.UuidField)
	alerts, err := RetrieveAlerts(m, m.AlertFilter.UuidField, m.AlertFilter.RuleName)
	if err != nil {
		log.Fatal("Failed to retrieve alerts")
		return false, err
	}
	// Filter the alerts, is the one we're looking for here?
	alerts = FilterByUuidPresence(alerts, detonationUuid)
	if len(alerts) == 1 {
		log.Info("One open alert found")
		m.AlertId = alerts[0].ID
		m.Index = alerts[0].Index
		return true, nil
	}
	if len(alerts) > 1 {
		// TODO: It may well be desirable for a suspicious event to trigger multiple alerts
		// In future ElasticsearchAlertGeneratedAssertion.AlertFilter should be a list, capable
		// of matching and closing multiple alerts associated with a single event.
		log.Errorf("More than one alert found")
		return false, nil
	}
	log.Warnf("No alerts found")
	return false, nil
}

func (m *ElasticsearchAlertGeneratedAssertion) String() string {
	return fmt.Sprintf("Elasticsearch alert '%s'", m.AlertFilter.RuleName)
}

func (m *ElasticsearchAlertGeneratedAssertion) Cleanup(detonationUuid string) error {
	log.Infof("Closing alert for detonation: %s, for rule: %s with AlertId: %s in Index: %s", detonationUuid, m.AlertFilter.RuleName, m.AlertId, m.Index)
	// If HasExpectedAlert() executed properly then m.AlertId ought to be set with the ID we need
	if m.AlertId == "" {
		return errors.New("AlertId not set, cannot close alert")
	}
	// We can query via the .siem-signals-default alias, however this isn't the actual index the document is in.
	// To write to the index we need the actual index ID. Fortunately that data is in the document and we should
	// have written that also when we ran HasExpectedAlert().
	if m.Index == "" {
		return errors.New("Index not set, cannot close alert")
	}	
	update_request_body := `
	{
		"doc": {
			"kibana.alert.workflow_status": "closed"
		}
	}`
	resp, err := m.AlertAPI.Update(m.Index, m.AlertId, strings.NewReader(update_request_body))
	log.Info("Logging the update API response:\n",resp, "\n")
	if err != nil {
		log.Errorf("Error while trying to update document: %s", m.AlertId)
		return err
	}

	return nil
}