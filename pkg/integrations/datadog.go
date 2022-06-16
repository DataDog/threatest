package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/DataDog/datadog-api-client-go/api/v2/datadog"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type DatadogAlertFilter struct {
	RuleName string `yaml:"rule-name"`
	Severity string
	// There might be other attributes in the future
}

type DatadogAlertGeneratedAssertion struct {
	apiClient   *datadog.APIClient
	ctx         context.Context
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
	builder.apiClient = datadog.NewAPIClient(cfg)
	builder.ctx = ctx
	builder.AlertFilter = &DatadogAlertFilter{RuleName: name}
	return builder
}
func (m *DatadogAlertGeneratedAssertionBuilder) WithSeverity(severity string) *DatadogAlertGeneratedAssertionBuilder {
	m.AlertFilter.Severity = severity
	return m
}
func (m *DatadogAlertGeneratedAssertionBuilder) HasExpectedAlert(executionUid string) (bool, error) {
	return m.DatadogAlertGeneratedAssertion.HasExpectedAlert(executionUid)
}

func (m *DatadogAlertGeneratedAssertionBuilder) Cleanup(uid string) error {
	return m.DatadogAlertGeneratedAssertion.Cleanup(uid)
}

func (m DatadogAlertGeneratedAssertion) HasExpectedAlert(executionUid string) (bool, error) {
	// TODO cache signal IDs and exclude them in the search to avoid checking multiple times the same signal
	query := m.buildDatadogSignalQuery()
	signals, err := m.findSignals(query)
	if err != nil {
		return false, errors.New("unable to search for Datadog security signal: " + err.Error())
	}

	if len(signals) == 0 {
		return false, nil
	}

	for i := range signals {
		signal := signals[i]
		if m.signalMatchesExecution(signal, executionUid) { //TODO low-prio unify naming of "uuid"/"uid"
			return true, nil
		}
	}
	return false, nil
}

func (m DatadogAlertGeneratedAssertion) Cleanup(uid string) error {
	signals, err := m.findSignals(fmt.Sprintf(
		`@workflow.triage.state:open`,
	))
	if err != nil {
		return errors.New("unable to search for Datadog security monitoring signals: " + err.Error())
	}

	for i := range signals {
		if m.signalMatchesExecution(signals[i], uid) {
			if err := m.closeAlert(*signals[i].Id); err != nil {
				return errors.New("unable to archive signal " + *signals[i].Id + ": " + err.Error())
			}
		}
	}

	return nil
}

func (m DatadogAlertGeneratedAssertion) closeAlert(alertId string) error {
	payload, _ := json.Marshal(map[string]interface{}{
		"state":          "archived",
		"archiveReason":  "testing_or_maintenance",
		"archiveComment": "End to end detection testing",
	})
	req, err := http.NewRequest(
		http.MethodPatch,
		"https://api.datadoghq.com"+fmt.Sprintf("/api/v1/security_analytics/signals/%s/state", alertId),
		bytes.NewBuffer(payload),
	)

	if err != nil {
		return err
	}
	keys := m.ctx.Value(datadog.ContextAPIKeys).(map[string]datadog.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", keys["apiKeyAuth"].Key)
	req.Header.Set("DD-APPLICATION-KEY", keys["appKeyAuth"].Key)

	client := &http.Client{}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return errors.New("unable to archive signal, got status code " + strconv.Itoa(response.StatusCode))
	}
	return nil
}

func (m DatadogAlertGeneratedAssertion) buildDatadogSignalQuery() string {
	severityQuery := ""
	if m.AlertFilter.Severity != "" {
		severityQuery = fmt.Sprintf("status:%s ", m.AlertFilter.Severity)
	}
	return fmt.Sprintf(
		`@workflow.triage.state:open @workflow.rule.name:"%s" %s`,
		m.AlertFilter.RuleName,
		severityQuery,
	)
}

func (m DatadogAlertGeneratedAssertion) findSignals(query string) ([]datadog.SecurityMonitoringSignal, error) {
	params := datadog.NewSearchSecurityMonitoringSignalsOptionalParameters().WithBody(datadog.SecurityMonitoringSignalListRequest{
		Filter: &datadog.SecurityMonitoringSignalListRequestFilter{
			From:  datadog.PtrTime(time.Now().Add(-1 * time.Hour)), // Signals no older than 1 hour
			Query: datadog.PtrString(query),
		},
		Page: &datadog.SecurityMonitoringSignalListRequestPage{Limit: datadog.PtrInt32(1000)}, // TODO
		Sort: datadog.SECURITYMONITORINGSIGNALSSORT_TIMESTAMP_DESCENDING.Ptr(),
	})

	logger := log.Default()
	logger.SetOutput(io.Discard) // suppress annoying warning output
	signals, _, err := m.apiClient.SecurityMonitoringApi.SearchSecurityMonitoringSignals(m.ctx, *params)
	logger.SetOutput(os.Stdout) // restore proper logging

	return signals.Data, err
}

func (m DatadogAlertGeneratedAssertion) signalMatchesExecution(signal datadog.SecurityMonitoringSignal, uid string) bool {
	buf, _ := json.Marshal(signal.Attributes.Attributes)
	rawSignal := string(buf)
	return strings.Contains(rawSignal, uid)
}
