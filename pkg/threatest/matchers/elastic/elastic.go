// Package elastic matches expected Elastic Security detection alerts.
package elastic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AlertLookbackWindow bounds how far back alerts are searched, mirroring the
// Datadog matcher which only considers signals from the past hour.
const AlertLookbackWindow = 1 * time.Hour

// ElasticSecurityDetectionAlert represents a security detection alert document in Elastic Security.
type ElasticSecurityDetectionAlert struct {
	ID     string                 `json:"_id"`
	Index  string                 `json:"_index"`
	Source map[string]interface{} `json:"_source"`
}

// ElasticSecurityDetectionEngineSearchResponse represents the response from the
// Kibana Detection Engine search API.
type ElasticSecurityDetectionEngineSearchResponse struct {
	Took int `json:"took"`
	Hits struct {
		Total struct {
			Value int `json:"value"`
		} `json:"total"`
		Hits []ElasticSecurityDetectionAlert `json:"hits"`
	} `json:"hits"`
}

type ElasticSecurityDetectionAlertsAPI interface {
	SearchAlerts(ctx context.Context, query string) ([]ElasticSecurityDetectionAlert, error)
	CloseAlert(ctx context.Context, id string) error
}

type ElasticSecurityDetectionAlertsAPIImpl struct {
	kibanaURL string
	apiKey    Secret
}

func (m *ElasticSecurityDetectionAlertsAPIImpl) SearchAlerts(ctx context.Context, query string) ([]ElasticSecurityDetectionAlert, error) {
	url := fmt.Sprintf("%s/api/detection_engine/signals/search", m.kibanaURL)

	log.Infof("Searching for Elastic Security alerts with query: %s", query)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(query))
	if err != nil {
		return nil, fmt.Errorf("error creating search request: %w", err)
	}
	m.setHeaders(req)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error executing search request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search failed with status code: %d", resp.StatusCode)
	}

	var searchResp ElasticSecurityDetectionEngineSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("error parsing search response: %w", err)
	}

	return searchResp.Hits.Hits, nil
}

func (m *ElasticSecurityDetectionAlertsAPIImpl) CloseAlert(ctx context.Context, id string) error {
	url := fmt.Sprintf("%s/api/detection_engine/signals/status", m.kibanaURL)

	payload, err := json.Marshal(map[string]interface{}{
		"signal_ids": []string{id},
		"status":     "closed",
	})
	if err != nil {
		return fmt.Errorf("error marshaling close alert payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	m.setHeaders(req)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error executing close alert request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("unable to close alert, got status code " + strconv.Itoa(resp.StatusCode))
	}

	return nil
}

func (m *ElasticSecurityDetectionAlertsAPIImpl) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "ApiKey "+m.apiKey.Value())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("kbn-xsrf", "true")
}

func (m *ElasticSecurityAlertGeneratedAssertionBuilder) HasExpectedAlert(ctx context.Context, detonationUuid string) (bool, error) {
	return m.ElasticSecurityAlertGeneratedAssertion.HasExpectedAlert(ctx, detonationUuid)
}

func (m *ElasticSecurityAlertGeneratedAssertionBuilder) Cleanup(ctx context.Context, detonationUuid string) error {
	return m.ElasticSecurityAlertGeneratedAssertion.Cleanup(ctx, detonationUuid)
}

func (m *ElasticSecurityAlertGeneratedAssertion) HasExpectedAlert(ctx context.Context, detonationUuid string) (bool, error) {
	query := m.buildElasticAlertQuery()
	alerts, err := m.AlertsAPI.SearchAlerts(ctx, query)
	if err != nil {
		return false, errors.New("unable to search for Elastic Security alert: " + err.Error())
	}

	if len(alerts) == 0 {
		return false, nil
	}

	for i := range alerts {
		if m.alertMatchesExecution(alerts[i], detonationUuid) {
			return true, nil
		}
	}

	return false, nil
}

func (m *ElasticSecurityAlertGeneratedAssertion) String() string {
	return fmt.Sprintf("Elastic Security alert '%s'", m.AlertFilter.RuleName)
}

func (m *ElasticSecurityAlertGeneratedAssertion) Cleanup(ctx context.Context, detonationUuid string) error {
	alerts, err := m.AlertsAPI.SearchAlerts(ctx, buildAllOpenAlertsQuery())
	if err != nil {
		return errors.New("unable to search for Elastic Security alerts: " + err.Error())
	}

	for i := range alerts {
		if m.alertMatchesExecution(alerts[i], detonationUuid) {
			if err := m.AlertsAPI.CloseAlert(ctx, alerts[i].ID); err != nil {
				return errors.New("unable to close alert " + alerts[i].ID + ": " + err.Error())
			}
		}
	}

	return nil
}

// buildElasticAlertQuery builds a Detection Engine query matching open alerts
// for the configured rule name (and severity, when set) within the lookback window.
func (m *ElasticSecurityAlertGeneratedAssertion) buildElasticAlertQuery() string {
	must := []map[string]interface{}{
		{"match_phrase": map[string]interface{}{"kibana.alert.rule.name": m.AlertFilter.RuleName}},
	}
	if m.AlertFilter.Severity != "" {
		must = append(must, map[string]interface{}{
			"match_phrase": map[string]interface{}{"kibana.alert.severity": m.AlertFilter.Severity},
		})
	}
	return buildQuery(must)
}

// buildAllOpenAlertsQuery builds a Detection Engine query matching all open
// alerts within the lookback window, regardless of rule name. It is used during
// cleanup to find any alert correlated to a detonation.
func buildAllOpenAlertsQuery() string {
	return buildQuery(nil)
}

func buildQuery(must []map[string]interface{}) string {
	type queryStruct struct {
		Size  int                      `json:"size"`
		Query map[string]interface{}   `json:"query"`
		Sort  []map[string]interface{} `json:"sort"`
	}

	boolQuery := map[string]interface{}{
		"filter": []map[string]interface{}{
			{"match_phrase": map[string]interface{}{"kibana.alert.workflow_status": "open"}},
			{"range": map[string]interface{}{"@timestamp": map[string]interface{}{"gte": sinceValue()}}},
		},
		"must_not": []map[string]interface{}{
			{"exists": map[string]interface{}{"field": "kibana.alert.building_block_type"}},
		},
	}
	if len(must) > 0 {
		boolQuery["must"] = must
	}

	query := queryStruct{
		Size:  1000,
		Query: map[string]interface{}{"bool": boolQuery},
		Sort: []map[string]interface{}{
			{"@timestamp": map[string]string{"order": "desc"}},
		},
	}

	queryBytes, _ := json.Marshal(query)
	return string(queryBytes)
}

// sinceValue returns the lower bound of the alert search window.
func sinceValue() string {
	return time.Now().Add(-AlertLookbackWindow).UTC().Format(time.RFC3339)
}

// alertMatchesExecution reports whether the alert's source document references
// the detonation UUID, signalling that the alert was caused by this detonation.
func (m *ElasticSecurityAlertGeneratedAssertion) alertMatchesExecution(alert ElasticSecurityDetectionAlert, uid string) bool {
	buf, _ := json.Marshal(alert.Source)
	return strings.Contains(string(buf), uid)
}
