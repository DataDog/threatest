package splunk

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// SplunkAPIConfig holds configuration for the Splunk API client
type SplunkAPIConfig struct {
	BaseURL            string
	AuthToken          string
	Username           string
	Password           string
	AppName            string
	InsecureSkipVerify bool
}

// SplunkAPIImpl implements the SplunkAPI interface
type SplunkAPIImpl struct {
	client    *http.Client
	baseURL   string
	authToken string
	username  string
	password  string
	ctx       context.Context
	appName   string
}

// Constants for Splunk API endpoints
const (
	SearchJobsEndpoint    = "/services/search/jobs"
	NotableUpdateEndpoint = "/services/notable_update"
)

// Ensure SplunkAPIImpl implements the SplunkAPI interface
//var _ api.SplunkAPI = &SplunkAPIImpl{}

// NewSplunkAPI creates a new SplunkAPI implementation
func NewSplunkAPI(config SplunkAPIConfig) *SplunkAPIImpl {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: config.InsecureSkipVerify},
	}
	client := &http.Client{Transport: tr}

	return &SplunkAPIImpl{
		client:    client,
		baseURL:   config.BaseURL,
		authToken: config.AuthToken,
		username:  config.Username,
		password:  config.Password,
		ctx:       context.Background(),
		appName:   config.AppName,
	}
}

// createRequest creates a new HTTP request with the appropriate headers for Splunk's API
func (api *SplunkAPIImpl) createRequest(method, endpoint string, body io.Reader) (*http.Request, error) {
	url := fmt.Sprintf("%s%s", api.baseURL, endpoint)
	req, err := http.NewRequestWithContext(api.ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	// Set auth header based on available credentials
	if api.authToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", api.authToken))
	} else if api.username != "" && api.password != "" {
		req.SetBasicAuth(api.username, api.password)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// closeBody safely closes an HTTP response body and logs any errors
func closeBody(body io.ReadCloser) {
	if body == nil {
		return
	}
	if err := body.Close(); err != nil {
		log.Warnf("Error closing response body: %v", err)
	}
}

// Splunk API Operations

// SearchNotables searches for notable events based on filter criteria
func (s *SplunkAPIImpl) SearchNotables(filter map[string]string) ([]map[string]interface{}, error) {
	// Convert map to SplunkNotableFilter
	internalFilter := SplunkNotableFilter{
		RuleName:     filter["RuleName"],
		Severity:     filter["Severity"],
		DetectionUID: filter["DetectionUID"],
		StartTime:    filter["StartTime"],
		EndTime:      filter["EndTime"],
	}

	// Build query and execute search
	searchQuery := s.buildNotableQuery(internalFilter)
	searchJobID, err := s.createSearchJob(searchQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to create notable search job: %w", err)
	}

	if err := s.waitForJobCompletion(searchJobID); err != nil {
		return nil, fmt.Errorf("failed waiting for notable search job: %w", err)
	}

	notables, err := s.getSearchResults(searchJobID)
	if err != nil {
		return nil, err
	}

	// Convert to map format for the interface
	results := make([]map[string]interface{}, len(notables))
	for i, notable := range notables {
		results[i] = notable.Custom
		results[i]["_id"] = notable.ID
		results[i]["_name"] = notable.Name
	}

	return results, nil
}

// buildNotableQuery builds a Splunk query for notable events
func (s *SplunkAPIImpl) buildNotableQuery(filter SplunkNotableFilter) string {
	// Start with search command
	queryStart := "search "

	// Add time parameters
	if filter.StartTime != "" {
		queryStart += fmt.Sprintf("earliest=%s ", filter.StartTime)
	}
	if filter.EndTime != "" {
		queryStart += fmt.Sprintf("latest=%s ", filter.EndTime)
	}

	// Add index name
	queryStart += "`notable`"

	// Build search conditions
	var conditions []string
	if filter.RuleName != "" {
		conditions = append(conditions, fmt.Sprintf("search_name=\"%s\"", filter.RuleName))
	}
	if filter.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity=\"%s\"", filter.Severity))
	}
	// Always add detectionuid condition if present
	if filter.DetectionUID != "" {
		conditions = append(conditions, fmt.Sprintf("%s", filter.DetectionUID))
	}

	// Combine into final query
	searchConditions := "search " + strings.Join(conditions, " ")
	log.Debugf("Final search query: %s", searchConditions)
	return fmt.Sprintf("%s | %s", queryStart, searchConditions)
}

// createSearchJob creates a new search job
func (s *SplunkAPIImpl) createSearchJob(query string) (string, error) {
	payload := fmt.Sprintf("search=%s", query)

	req, err := s.createRequest("POST", SearchJobsEndpoint+"?output_mode=json", strings.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create search request: %w", err)
	}

	log.Debugf("Creating search job with URL: %s", req.URL.String())
	log.Debugf("Query: %s", query)

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute search request: %w", err)
	}
	defer closeBody(resp.Body)

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("search request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		SID string `json:"sid"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse job response: %w", err)
	}

	return result.SID, nil
}

// waitForJobCompletion waits for a search job to complete
func (s *SplunkAPIImpl) waitForJobCompletion(jobID string) error {
	statusEndpoint := fmt.Sprintf("%s/%s?output_mode=json", SearchJobsEndpoint, jobID)

	log.Debugf("Starting job status check for job %s", jobID)

	maxAttempts := 30
	for i := 0; i < maxAttempts; i++ {
		req, err := s.createRequest("GET", statusEndpoint, nil)
		if err != nil {
			return fmt.Errorf("failed to create status request: %w", err)
		}

		log.Debugf("Checking job status (attempt %d/%d): %s",
			i+1, maxAttempts, req.URL.String())

		resp, err := s.client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to check job status: %w", err)
		}

		var status struct {
			Entry []struct {
				Content struct {
					IsDone bool `json:"isDone"`
				} `json:"content"`
			} `json:"entry"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
			closeBody(resp.Body)
			return fmt.Errorf("failed to parse status response: %w", err)
		}
		closeBody(resp.Body)

		if len(status.Entry) > 0 && status.Entry[0].Content.IsDone {
			return nil
		}

		// Add a sleep between check attempts to help mitigate API spamming
		time.Sleep(2 * time.Second)
	}

	return errors.New("job timed out")
}

// getSearchResults gets results from a completed search job
func (s *SplunkAPIImpl) getSearchResults(jobID string) ([]SplunkNotable, error) {
	resultsEndpoint := fmt.Sprintf("%s/%s/results?output_mode=json", SearchJobsEndpoint, jobID)

	log.Debugf("Getting search results from job %s", jobID)

	req, err := s.createRequest("GET", resultsEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create results request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get search results: %w", err)
	}
	defer closeBody(resp.Body)

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get search results with status %d: %s", resp.StatusCode, string(body))
	}

	var results struct {
		Results []map[string]interface{} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, fmt.Errorf("failed to parse results: %w", err)
	}

	notables := make([]SplunkNotable, 0, len(results.Results))
	for _, result := range results.Results {
		// Extract relevant fields from the result
		notable := SplunkNotable{
			ID:     fmt.Sprintf("%v", result["event_id"]), // This is the notable UID
			Name:   fmt.Sprintf("%v", result["search_name"]),
			Custom: result,
		}

		if severity, ok := result["severity"]; ok {
			notable.Severity = fmt.Sprintf("%v", severity)
		}

		notables = append(notables, notable)
	}

	return notables, nil
}

// CloseNotable closes a notable event
func (s *SplunkAPIImpl) CloseNotable(id string) error {
	payload := fmt.Sprintf("ruleUIDs=%s&status=5&comment=Closed by Threatest", id)

	log.Infof("Closing Splunk notable %s", id)

	req, err := s.createRequest("POST", NotableUpdateEndpoint, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create notable update request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute notable update request: %w", err)
	}
	defer closeBody(resp.Body)

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("notable update failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// notableMatchesExecution checks if a notable matches a specific execution
func (m *SplunkNotableGeneratedAssertion) notableMatchesExecution(notable map[string]interface{}, executionID string) bool {
	data, _ := json.Marshal(notable)
	rawNotable := string(data)
	return strings.Contains(rawNotable, executionID)
}

// HasExpectedAlert checks if an expected notable exists
func (m *SplunkNotableGeneratedAssertion) HasExpectedAlert(executionID string) (bool, error) {
	// Create a map from the filter
	filterMap := convertFilterToMap(m.NotableFilter)

	// Store the executionID in the filter map
	filterMap["DetectionUID"] = executionID

	notables, err := m.SplunkAPI.SearchNotables(filterMap)
	if err != nil {
		return false, fmt.Errorf("unable to search for Splunk notables: %w", err)
	}

	for _, notable := range notables {
		if m.notableMatchesExecution(notable, executionID) {
			return true, nil
		}
	}

	return false, nil
}

// performActionOnMatchingNotables performs an action on all matching notables
func (m *SplunkNotableGeneratedAssertion) performActionOnMatchingNotables(executionID string, actionName string) error {
	filterMap := convertFilterToMap(m.NotableFilter)
	filterMap["DetectionUID"] = executionID

	notables, err := m.SplunkAPI.SearchNotables(filterMap)
	if err != nil {
		return fmt.Errorf("unable to search for Splunk notables: %w", err)
	}

	for _, notable := range notables {
		if m.notableMatchesExecution(notable, executionID) {
			id := fmt.Sprintf("%v", notable["_id"])
			if err := m.SplunkAPI.CloseNotable(id); err != nil {
				return fmt.Errorf("unable to %s notable %s: %w", actionName, id, err)
			}
		}
	}

	return nil
}

// Assert checks for matching notables and closes them
func (m *SplunkNotableGeneratedAssertion) Assert(executionID string) error {
	return m.performActionOnMatchingNotables(executionID, "assert")
}

// Cleanup removes any notables associated with the execution
func (m *SplunkNotableGeneratedAssertion) Cleanup(executionID string) error {
	log.Infof("Starting cleanup for Splunk notables related to execution ID: %s", executionID)
	return m.performActionOnMatchingNotables(executionID, "cleanup")
}

// String returns a string representation of the assertion
func (m *SplunkNotableGeneratedAssertion) String() string {
	return fmt.Sprintf("Splunk notable '%s'", m.NotableFilter.RuleName)
}

// SplunkNotableEvent creates a new builder for SplunkNotableGeneratedAssertion
func SplunkNotableEvent(ruleName string) *SplunkNotableGeneratedAssertionBuilder {
	builder := &SplunkNotableGeneratedAssertionBuilder{}

	// Use environment variables for configuration
	baseUrl := os.Getenv("SPLUNK_BASE_URL")
	if baseUrl == "" {
		baseUrl = "https://localhost:8089"
	}

	authToken := os.Getenv("SPLUNK_AUTH_TOKEN")
	username := os.Getenv("SPLUNK_USERNAME")
	password := os.Getenv("SPLUNK_PASSWORD")

	// Default to false for insecureSkipVerify
	skipVerify := false
	if os.Getenv("SPLUNK_INSECURE_SKIP_VERIFY") == "true" {
		skipVerify = true
	}

	apiConfig := SplunkAPIConfig{
		BaseURL:            baseUrl,
		AuthToken:          authToken,
		Username:           username,
		Password:           password,
		InsecureSkipVerify: skipVerify,
	}

	builder.SplunkAPI = NewSplunkAPI(apiConfig)
	builder.NotableFilter = SplunkNotableFilter{RuleName: ruleName}

	return builder
}

// Factory function for the new builder pattern
func (b *SplunkNotableGeneratedAssertionBuilder) Build() *SplunkNotableGeneratedAssertion {
	return &b.SplunkNotableGeneratedAssertion
}

// Helper function to convert SplunkNotableFilter to map
func convertFilterToMap(filter SplunkNotableFilter) map[string]string {
	result := make(map[string]string)

	if filter.RuleName != "" {
		result["RuleName"] = filter.RuleName
	}
	if filter.Severity != "" {
		result["Severity"] = filter.Severity
	}
	if filter.DetectionUID != "" {
		result["DetectionUID"] = filter.DetectionUID
	}
	if filter.StartTime != "" {
		result["StartTime"] = filter.StartTime
	}
	if filter.EndTime != "" {
		result["EndTime"] = filter.EndTime
	}

	return result
}
