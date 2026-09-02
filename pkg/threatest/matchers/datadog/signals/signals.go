package signals

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/aws/smithy-go/ptr"
	"github.com/datadog/threatest/pkg/threatest/matchers"
	"github.com/datadog/threatest/pkg/threatest/matchers/datadog/shared"
	log "github.com/sirupsen/logrus"
)

const lookbackWindow = 15 * time.Minute
const maxResults = 1000

const QueryAllOpenSignals = `@workflow.triage.state:open`
const queryRelatedSignalsByUUID = `@workflow.triage.state:open *:*%s*`
const QueryOpenSignalsByAlertNameAndSeverity = `@workflow.triage.state:open @workflow.rule.name:"%s" %s`
const QuerySeverity = `status:%s`

type SignalsAPI interface {
	SearchSignals(ctx context.Context, query string, opts ...matchers.SearchOption) ([]datadogV2.SecurityMonitoringSignal, error)
	CloseSignal(ctx context.Context, id string) error
}

type SignalsAPIImpl struct {
	api    *datadogV2.SecurityMonitoringApi
	creds  shared.APICredentials
	client *http.Client
}

func NewSignalsAPI(creds shared.APICredentials) SignalsAPI {
	return &SignalsAPIImpl{
		api:    datadogV2.NewSecurityMonitoringApi(datadog.NewAPIClient(datadog.NewConfiguration())),
		creds:  creds,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (m *SignalsAPIImpl) SearchSignals(ctx context.Context, query string, opts ...matchers.SearchOption) ([]datadogV2.SecurityMonitoringSignal, error) {
	o := matchers.ResolveOpts(opts)
	from := time.Now().Add(-lookbackWindow)
	to := time.Now()
	if !o.From.IsZero() {
		from = o.From
	}
	if !o.To.IsZero() {
		to = o.To
	}
	params := datadogV2.NewSearchSecurityMonitoringSignalsOptionalParameters().WithBody(datadogV2.SecurityMonitoringSignalListRequest{
		Filter: &datadogV2.SecurityMonitoringSignalListRequestFilter{
			From:  datadog.PtrTime(from),
			To:    datadog.PtrTime(to),
			Query: datadog.PtrString(query),
		},
		Page: &datadogV2.SecurityMonitoringSignalListRequestPage{Limit: ptr.Int32(int32(maxResults))},
		Sort: datadogV2.SECURITYMONITORINGSIGNALSSORT_TIMESTAMP_DESCENDING.Ptr(),
	})

	ddCtx := m.creds.BuildContext(ctx)
	signals, _, err := m.api.SearchSecurityMonitoringSignals(ddCtx, *params)
	if err != nil {
		return nil, err
	}
	if len(signals.Data) >= maxResults {
		log.Warnf("at least %d signals returned, returning first %d", maxResults, maxResults)
	}
	return signals.Data, nil
}

func (m *SignalsAPIImpl) CloseSignal(ctx context.Context, id string) error {
	payload, _ := json.Marshal(map[string]any{
		"state":          "archived",
		"archiveReason":  "testing_or_maintenance",
		"archiveComment": "End to end detection testing",
	})
	path := fmt.Sprintf("api/v1/security_analytics/signals/%s/state", id)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPatch,
		m.creds.APIBaseURL()+"/"+path,
		bytes.NewBuffer(payload),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", m.creds.APIKey.Value())
	req.Header.Set("DD-APPLICATION-KEY", m.creds.AppKey.Value())

	client := m.client
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}()
	if response.StatusCode != 200 {
		return fmt.Errorf("unable to archive signal, got status code %d", response.StatusCode)
	}
	return nil
}

type Filter struct {
	RuleName string
	Severity string
}

type Matcher struct {
	SignalsAPI SignalsAPI
	Filter     *Filter
}

type Builder struct {
	Matcher
}

type Option func(*Builder)

func WithCredentials(apiKey, appKey, site string) Option {
	return func(b *Builder) {
		b.SignalsAPI = NewSignalsAPI(shared.NewCredentials(apiKey, appKey, site))
	}
}

func WithSeverity(severity string) Option {
	return func(b *Builder) {
		b.Filter.Severity = severity
	}
}

func DatadogSecuritySignal(name string, opts ...Option) *Builder {
	builder := &Builder{}
	builder.SignalsAPI = NewSignalsAPI(shared.CredentialsFromEnv())
	builder.Filter = &Filter{RuleName: name}
	for _, opt := range opts {
		opt(builder)
	}
	return builder
}

func (m *Matcher) HasExpected(ctx context.Context, correlationID string) (bool, error) {
	query := m.buildSignalQuery()
	signals, err := m.SignalsAPI.SearchSignals(ctx, query)
	if err != nil {
		return false, fmt.Errorf("unable to search for Datadog security signal: %w", err)
	}
	if len(signals) == 0 {
		return false, nil
	}
	for i := range signals {
		if m.signalMatchesExecution(signals[i], correlationID) {
			return true, nil
		}
	}
	return false, nil
}

func (m *Matcher) Related(ctx context.Context, correlationID string) (map[string]matchers.ThreatestEvent, error) {
	query := fmt.Sprintf(queryRelatedSignalsByUUID, correlationID)
	signals, err := m.SignalsAPI.SearchSignals(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("unable to search for Datadog security monitoring signals: %w", err)
	}
	result := make(map[string]matchers.ThreatestEvent)
	for i := range signals {
		converted := convertSignal(signals[i])
		id, ok := converted.Attributes["id"].(string)
		if !ok || id == "" {
			continue
		}
		result[id] = converted
	}
	return result, nil
}

func (m *Matcher) Search(ctx context.Context, query string, opts ...matchers.SearchOption) (map[string]matchers.ThreatestEvent, error) {
	signals, err := m.SignalsAPI.SearchSignals(ctx, query, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to search for Datadog security monitoring signals: %w", err)
	}
	result := make(map[string]matchers.ThreatestEvent)
	for i := range signals {
		converted := convertSignal(signals[i])
		id, ok := converted.Attributes["id"].(string)
		if !ok || id == "" {
			continue
		}
		result[id] = converted
	}
	return result, nil
}

func (m *Matcher) String() string {
	name := m.Filter.RuleName
	if name == "" {
		name = "default correlation"
	}
	return fmt.Sprintf("Datadog security signal '%s'", name)
}

func (m *Matcher) Cleanup(ctx context.Context, correlationID string) error {
	signals, err := m.SignalsAPI.SearchSignals(ctx, QueryAllOpenSignals)
	if err != nil {
		return fmt.Errorf("unable to search for Datadog security monitoring signals: %w", err)
	}
	for i := range signals {
		if signals[i].Id == nil {
			continue
		}
		if m.signalMatchesExecution(signals[i], correlationID) {
			if err := m.SignalsAPI.CloseSignal(ctx, *signals[i].Id); err != nil {
				return fmt.Errorf("unable to archive signal %s: %w", *signals[i].Id, err)
			}
		}
	}
	return nil
}

func (m *Matcher) buildSignalQuery() string {
	severityQuery := ""
	if m.Filter.Severity != "" {
		severityQuery = fmt.Sprintf(QuerySeverity, m.Filter.Severity) + " "
	}
	return fmt.Sprintf(QueryOpenSignalsByAlertNameAndSeverity, m.Filter.RuleName, severityQuery)
}

func (m *Matcher) signalMatchesExecution(signal datadogV2.SecurityMonitoringSignal, correlationID string) bool {
	custom := extractCustom(signal)
	buf, _ := json.Marshal(custom)
	return strings.Contains(string(buf), correlationID)
}

func convertSignal(signal datadogV2.SecurityMonitoringSignal) matchers.ThreatestEvent {
	attrs := map[string]any{}
	if signal.Id != nil {
		attrs["id"] = *signal.Id
	}
	custom := extractCustom(signal)
	maps.Copy(attrs, custom)
	var ts time.Time
	if signal.Attributes != nil {
		attrs["tags"] = signal.Attributes.Tags
		if signal.Attributes.Timestamp != nil {
			ts = *signal.Attributes.Timestamp
		}
	}
	raw, _ := json.Marshal(signal)
	return matchers.ThreatestEvent{
		EventName:  "signal",
		Time:       ts,
		Attributes: attrs,
		Body:       raw,
	}
}

func extractCustom(signal datadogV2.SecurityMonitoringSignal) map[string]any {
	if signal.Attributes == nil {
		return nil
	}
	custom := signal.Attributes.Custom
	if custom == nil {
		if ap := signal.Attributes.AdditionalProperties; ap != nil {
			if v, ok := ap["attributes"]; ok {
				custom, _ = v.(map[string]any)
			}
		}
	}
	return custom
}
