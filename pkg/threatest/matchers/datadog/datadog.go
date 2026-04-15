package datadog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/aws/smithy-go/ptr"
)

const QueryAllOpenSignals = `@workflow.triage.state:open`
const QueryOpenSignalsByAlertNameAndSeverity = `@workflow.triage.state:open @workflow.rule.name:"%s" %s`
const QuerySeverity = `status:%s`

type DatadogSecuritySignalsAPI interface {
	SearchSignals(ctx context.Context, query string) ([]datadogV2.SecurityMonitoringSignal, error)
	CloseSignal(ctx context.Context, id string) error
}

type DatadogSecuritySignalsAPIImpl struct {
	securityMonitoringAPI *datadogV2.SecurityMonitoringApi
	apiKey                Secret
	appKey                Secret
	site                  string
}

func (m *DatadogSecuritySignalsAPIImpl) buildContext(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, datadog.ContextAPIKeys, map[string]datadog.APIKey{
		"apiKeyAuth": {Key: m.apiKey.Value()},
		"appKeyAuth": {Key: m.appKey.Value()},
	})
	ctx = context.WithValue(ctx, datadog.ContextServerVariables, map[string]string{
		"site": m.site,
	})
	return ctx
}

func (m *DatadogSecuritySignalsAPIImpl) SearchSignals(ctx context.Context, query string) ([]datadogV2.SecurityMonitoringSignal, error) {
	maxSignals := 1000
	params := datadogV2.NewSearchSecurityMonitoringSignalsOptionalParameters().WithBody(datadogV2.SecurityMonitoringSignalListRequest{
		Filter: &datadogV2.SecurityMonitoringSignalListRequestFilter{
			From:  datadog.PtrTime(time.Now().Add(-1 * time.Hour)), // Signals no older than 1 hour
			Query: datadog.PtrString(query),
		},
		Page: &datadogV2.SecurityMonitoringSignalListRequestPage{Limit: ptr.Int32(int32(maxSignals))},
		Sort: datadogV2.SECURITYMONITORINGSIGNALSSORT_TIMESTAMP_DESCENDING.Ptr(),
	})

	ddCtx := m.buildContext(ctx)
	signals, _, err := m.securityMonitoringAPI.SearchSecurityMonitoringSignals(ddCtx, *params)

	if len(signals.Data) >= maxSignals {
		return nil, errors.New("unsupported: more than 1000 open signals") // todo: paginate response
	}
	return signals.Data, err
}

func (m *DatadogSecuritySignalsAPIImpl) CloseSignal(ctx context.Context, id string) error {
	payload, _ := json.Marshal(map[string]interface{}{
		"state":          "archived",
		"archiveReason":  "testing_or_maintenance",
		"archiveComment": "End to end detection testing",
	})
	path := fmt.Sprintf("api/v1/security_analytics/signals/%s/state", id)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPatch,
		fmt.Sprintf("https://api.%s/%s", m.site, path),
		bytes.NewBuffer(payload),
	)

	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", m.apiKey.Value())
	req.Header.Set("DD-APPLICATION-KEY", m.appKey.Value())

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

func (m *DatadogAlertGeneratedAssertionBuilder) HasExpectedAlert(ctx context.Context, detonationUuid string) (bool, error) {
	return m.DatadogAlertGeneratedAssertion.HasExpectedAlert(ctx, detonationUuid)
}

func (m *DatadogAlertGeneratedAssertionBuilder) Cleanup(ctx context.Context, detonationUuid string) error {
	return m.DatadogAlertGeneratedAssertion.Cleanup(ctx, detonationUuid)
}

func (m *DatadogAlertGeneratedAssertion) HasExpectedAlert(ctx context.Context, detonationUuid string) (bool, error) {
	query := m.buildDatadogSignalQuery()
	signals, err := m.SignalsAPI.SearchSignals(ctx, query)
	if err != nil {
		return false, errors.New("unable to search for Datadog security signal: " + err.Error())
	}

	if len(signals) == 0 {
		return false, nil
	}

	for i := range signals {
		if m.signalMatchesExecution(signals[i], detonationUuid) { //TODO low-prio unify naming of "uuid"/"uid"
			return true, nil
		}
	}

	return false, nil
}

func (m *DatadogAlertGeneratedAssertion) String() string {
	return fmt.Sprintf("Datadog security signal '%s'", m.AlertFilter.RuleName)
}

func (m *DatadogAlertGeneratedAssertion) Cleanup(ctx context.Context, detonationUuid string) error {
	signals, err := m.SignalsAPI.SearchSignals(ctx, QueryAllOpenSignals)
	if err != nil {
		return errors.New("unable to search for Datadog security monitoring signals: " + err.Error())
	}

	for i := range signals {
		if m.signalMatchesExecution(signals[i], detonationUuid) {
			if err := m.SignalsAPI.CloseSignal(ctx, *signals[i].Id); err != nil {
				return errors.New("unable to archive signal " + *signals[i].Id + ": " + err.Error())
			}
		}
	}

	return nil
}

// TODO: Would probably make more sense to retrieve all open signal and iterate instead of doing 2 pass
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

func (m *DatadogAlertGeneratedAssertion) signalMatchesExecution(signal datadogV2.SecurityMonitoringSignal, uid string) bool {
	buf, _ := json.Marshal(signal.Attributes.Custom)
	rawSignal := string(buf)
	return strings.Contains(rawSignal, uid)
}
