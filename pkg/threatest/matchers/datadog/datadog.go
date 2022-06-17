package datadog

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

const QueryAllOpenSignals = `@workflow.triage.state:open`
const QueryOpenSignalsByAlertNameAndSeverity = `@workflow.triage.state:open @workflow.rule.name:"%s" %s`
const QuerySeverity = `status:%s`

type DatadogSecuritySignalsAPI interface {
	SearchSignals(query string) ([]datadog.SecurityMonitoringSignal, error)
	CloseSignal(id string) error
}

type DatadogSecuritySignalsAPIImpl struct {
	apiClient *datadog.APIClient
	ctx       context.Context
}

func (m *DatadogSecuritySignalsAPIImpl) SearchSignals(query string) ([]datadog.SecurityMonitoringSignal, error) {
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

func (m *DatadogSecuritySignalsAPIImpl) CloseSignal(id string) error {
	payload, _ := json.Marshal(map[string]interface{}{
		"state":          "archived",
		"archiveReason":  "testing_or_maintenance",
		"archiveComment": "End to end detection testing",
	})
	req, err := http.NewRequest(
		http.MethodPatch,
		"https://api.datadoghq.com"+fmt.Sprintf("/api/v1/security_analytics/signals/%s/state", id),
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

func (m *DatadogAlertGeneratedAssertionBuilder) HasExpectedAlert(executionUid string) (bool, error) {
	return m.DatadogAlertGeneratedAssertion.HasExpectedAlert(executionUid)
}

func (m *DatadogAlertGeneratedAssertionBuilder) Cleanup(uid string) error {
	return m.DatadogAlertGeneratedAssertion.Cleanup(uid)
}

func (m *DatadogAlertGeneratedAssertion) HasExpectedAlert(executionUid string) (bool, error) {
	// TODO cache signal IDs and exclude them in the search to avoid checking multiple times the same signal
	query := m.buildDatadogSignalQuery()
	signals, err := m.SignalsAPI.SearchSignals(query)
	if err != nil {
		return false, errors.New("unable to search for Datadog security signal: " + err.Error())
	}

	if len(signals) == 0 {
		return false, nil
	}

	for i := range signals {
		if m.signalMatchesExecution(signals[i], executionUid) { //TODO low-prio unify naming of "uuid"/"uid"
			return true, nil
		}
	}

	return false, nil
}

func (m *DatadogAlertGeneratedAssertion) String() string {
	return fmt.Sprintf("Datadog security signal '%s'", m.AlertFilter.RuleName)
}

func (m *DatadogAlertGeneratedAssertion) Cleanup(uid string) error {
	signals, err := m.SignalsAPI.SearchSignals(QueryAllOpenSignals)
	if err != nil {
		return errors.New("unable to search for Datadog security monitoring signals: " + err.Error())
	}

	for i := range signals {
		if m.signalMatchesExecution(signals[i], uid) {
			if err := m.SignalsAPI.CloseSignal(*signals[i].Id); err != nil {
				return errors.New("unable to archive signal " + *signals[i].Id + ": " + err.Error())
			}
		}
	}

	return nil
}

//TODO: Would probably make more sense to retrieve all open signal and iterate instead of doing 2 pass
func (m *DatadogAlertGeneratedAssertion) buildDatadogSignalQuery() string {
	severityQuery := ""
	if m.AlertFilter.Severity != "" {
		severityQuery = fmt.Sprintf(QuerySeverity, m.AlertFilter.Severity) + " "
	}
	return fmt.Sprintf(
		QueryOpenSignalsByAlertNameAndSeverity,
		m.AlertFilter.RuleName,
		severityQuery,
	)
}

func (m *DatadogAlertGeneratedAssertion) signalMatchesExecution(signal datadog.SecurityMonitoringSignal, uid string) bool {
	buf, _ := json.Marshal(signal.Attributes.Attributes)
	rawSignal := string(buf)
	return strings.Contains(rawSignal, uid)
}
