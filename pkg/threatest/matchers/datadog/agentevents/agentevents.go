package agentevents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/datadog/threatest/pkg/threatest/matchers"
	"github.com/datadog/threatest/pkg/threatest/matchers/datadog/shared"
	"github.com/datadog/threatest/pkg/threatest/querybuilder"
	log "github.com/sirupsen/logrus"
)

const lookbackWindow = 15 * time.Minute
const maxResults = 1000

const defaultEventCorrelationQuery = "stratus-red-team"

type EventsAPI interface {
	SearchEvents(ctx context.Context, query string, opts ...matchers.SearchOption) ([]map[string]any, error)
}

type EventsAPIImpl struct {
	creds  shared.APICredentials
	client *http.Client
}

func NewEventsAPI(creds shared.APICredentials) EventsAPI {
	return &EventsAPIImpl{
		creds:  creds,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (m *EventsAPIImpl) SearchEvents(ctx context.Context, query string, opts ...matchers.SearchOption) ([]map[string]any, error) {
	o := matchers.ResolveOpts(opts)
	now := time.Now().UnixMilli()
	from := now - lookbackWindow.Milliseconds()
	if !o.From.IsZero() {
		from = o.From.UnixMilli()
	}
	if !o.To.IsZero() {
		now = o.To.UnixMilli()
	}
	body := map[string]any{
		"list": map[string]any{
			"limit":                maxResults,
			"time":                 map[string]any{"from": from, "to": now},
			"search":               map[string]any{"query": query},
			"includeEvents":        true,
			"includeEventContents": true,
			"computeCount":         false,
			"indexes":              []string{"*"},
			"sorts":                []map[string]any{{"time": map[string]any{"order": "desc"}}},
		},
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		m.creds.APIBaseURL()+"/api/v1/logs-analytics/list?type=secruntime",
		bytes.NewBuffer(payload),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DD-API-KEY", m.creds.APIKey.Value())
	req.Header.Set("DD-APPLICATION-KEY", m.creds.AppKey.Value())

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("logs-analytics request failed with status code %d", resp.StatusCode)
	}

	var result struct {
		Result struct {
			Events []map[string]any `json:"events"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("error parsing logs-analytics response: %w", err)
	}
	if len(result.Result.Events) >= maxResults {
		log.Warnf("at least %d events returned, returning first %d", maxResults, maxResults)
	}
	return result.Result.Events, nil
}

type Filter struct {
	Query string
}

type Matcher struct {
	EventsAPI EventsAPI
	Filter    *Filter
}

type Builder struct {
	Matcher
}

type Option func(*Builder)

func WithCredentials(apiKey, appKey, site string) Option {
	return func(b *Builder) {
		b.EventsAPI = NewEventsAPI(shared.NewCredentials(apiKey, appKey, site))
	}
}

func WithQuery(query string) Option {
	return func(b *Builder) {
		b.Filter.Query = query
	}
}

func DatadogAgentEvent(opts ...Option) *Builder {
	builder := &Builder{}
	builder.EventsAPI = NewEventsAPI(shared.CredentialsFromEnv())
	builder.Filter = &Filter{}
	for _, opt := range opts {
		opt(builder)
	}
	return builder
}

func (m *Matcher) HasExpected(ctx context.Context, correlationID string) (bool, error) {
	events, err := m.Related(ctx, correlationID)
	if err != nil {
		return false, err
	}
	return len(events) > 0, nil
}

func (m *Matcher) Related(ctx context.Context, correlationID string) (map[string]matchers.ThreatestEvent, error) {
	query := querybuilder.SubstituteQuery(m.defaultCorrelationQuery(), querybuilder.CorrelationVars{CorrelationID: correlationID})
	return m.Search(ctx, query)
}

func (m *Matcher) Search(ctx context.Context, query string, opts ...matchers.SearchOption) (map[string]matchers.ThreatestEvent, error) {
	ddEvents, err := m.EventsAPI.SearchEvents(ctx, query, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to search Datadog agent events: %w", err)
	}
	result := make(map[string]matchers.ThreatestEvent)
	for i := range ddEvents {
		converted := convertEvent(ddEvents[i])
		id, ok := converted.Attributes["id"].(string)
		if !ok || id == "" {
			continue
		}
		result[id] = converted
	}
	return result, nil
}

func (m *Matcher) String() string {
	query := m.Filter.Query
	if query == "" {
		query = "default correlation"
	}
	return fmt.Sprintf("Datadog agent events matching '%s'", query)
}

func (m *Matcher) Cleanup(ctx context.Context, correlationID string) error {
	return nil
}

func (m *Matcher) defaultCorrelationQuery() string {
	if m.Filter.Query != "" {
		return m.Filter.Query
	}
	return defaultEventCorrelationQuery
}

func convertEvent(ddEvent map[string]any) matchers.ThreatestEvent {
	attrs := map[string]any{}
	for k, v := range ddEvent {
		attrs[k] = v
	}
	var eventTime time.Time
	if ts, ok := attrs["timestamp"]; ok {
		switch t := ts.(type) {
		case string:
			eventTime, _ = time.Parse(time.RFC3339, t)
		case float64:
			eventTime = time.UnixMilli(int64(t))
		}
	}
	raw, _ := json.Marshal(ddEvent)
	return matchers.ThreatestEvent{
		EventName:  "agent-event",
		Time:       eventTime,
		Attributes: attrs,
		Body:       raw,
	}
}
