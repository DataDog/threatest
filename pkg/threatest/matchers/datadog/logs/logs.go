package logs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/aws/smithy-go/ptr"
	"github.com/datadog/threatest/pkg/threatest/matchers"
	"github.com/datadog/threatest/pkg/threatest/matchers/datadog/shared"
	"github.com/datadog/threatest/pkg/threatest/querybuilder"
	log "github.com/sirupsen/logrus"
)

const lookbackWindow = 15 * time.Minute
const maxResults = 1000

type LogsAPI interface {
	SearchLogs(ctx context.Context, query string, opts ...matchers.SearchOption) ([]datadogV2.Log, error)
}

type LogsAPIImpl struct {
	api   *datadogV2.LogsApi
	creds shared.APICredentials
}

func NewLogsAPI(creds shared.APICredentials) LogsAPI {
	return &LogsAPIImpl{
		api:   datadogV2.NewLogsApi(datadog.NewAPIClient(datadog.NewConfiguration())),
		creds: creds,
	}
}

func (m *LogsAPIImpl) SearchLogs(ctx context.Context, query string, opts ...matchers.SearchOption) ([]datadogV2.Log, error) {
	o := matchers.ResolveOpts(opts)
	from := time.Now().Add(-lookbackWindow).Format(time.RFC3339)
	to := time.Now().Format(time.RFC3339)
	if !o.From.IsZero() {
		from = o.From.Format(time.RFC3339)
	}
	if !o.To.IsZero() {
		to = o.To.Format(time.RFC3339)
	}
	params := datadogV2.NewListLogsOptionalParameters().WithBody(datadogV2.LogsListRequest{
		Filter: &datadogV2.LogsQueryFilter{
			From:  datadog.PtrString(from),
			To:    datadog.PtrString(to),
			Query: datadog.PtrString(query),
		},
		Page: &datadogV2.LogsListRequestPage{Limit: ptr.Int32(int32(maxResults))},
		Sort: datadogV2.LOGSSORT_TIMESTAMP_DESCENDING.Ptr(),
	})

	ddCtx := m.creds.BuildContext(ctx)
	logs, _, err := m.api.ListLogs(ddCtx, *params)
	if err != nil {
		return nil, err
	}
	if len(logs.GetData()) >= maxResults {
		log.Warnf("at least %d logs returned, returning first %d", maxResults, maxResults)
	}
	return logs.GetData(), nil
}

type Filter struct {
	Query string
}

type Matcher struct {
	LogsAPI LogsAPI
	Filter  *Filter
}

type Builder struct {
	Matcher
}

type Option func(*Builder)

func WithCredentials(apiKey, appKey, site string) Option {
	return func(b *Builder) {
		b.LogsAPI = NewLogsAPI(shared.NewCredentials(apiKey, appKey, site))
	}
}

func WithQuery(query string) Option {
	return func(b *Builder) {
		b.Filter.Query = query
	}
}

func DatadogLog(opts ...Option) *Builder {
	builder := &Builder{}
	builder.LogsAPI = NewLogsAPI(shared.CredentialsFromEnv())
	builder.Filter = &Filter{}
	for _, opt := range opts {
		opt(builder)
	}
	return builder
}

func (m *Matcher) HasExpected(ctx context.Context, correlationID string) (bool, error) {
	logs, err := m.Related(ctx, correlationID)
	if err != nil {
		return false, err
	}
	return len(logs) > 0, nil
}

func (m *Matcher) Related(ctx context.Context, correlationID string) (map[string]matchers.ThreatestEvent, error) {
	query := querybuilder.SubstituteQuery(m.defaultCorrelationQuery(correlationID), querybuilder.CorrelationVars{CorrelationID: correlationID})
	return m.Search(ctx, query)
}

func (m *Matcher) Search(ctx context.Context, query string, opts ...matchers.SearchOption) (map[string]matchers.ThreatestEvent, error) {
	ddLogs, err := m.LogsAPI.SearchLogs(ctx, query, opts...)
	if err != nil {
		return nil, fmt.Errorf("unable to search Datadog logs: %w", err)
	}
	result := make(map[string]matchers.ThreatestEvent)
	for i := range ddLogs {
		converted := convertLog(ddLogs[i])
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
	return fmt.Sprintf("Datadog logs matching '%s'", query)
}

func (m *Matcher) Cleanup(ctx context.Context, correlationID string) error {
	return nil
}

func (m *Matcher) defaultCorrelationQuery(correlationID string) string {
	if m.Filter.Query != "" {
		return m.Filter.Query
	}
	return fmt.Sprintf("*:*%s*", correlationID)
}

func convertLog(ddLog datadogV2.Log) matchers.ThreatestEvent {
	attrs := map[string]any{}
	if ddLog.Id != nil {
		attrs["id"] = *ddLog.Id
	}
	logAttrs := ddLog.GetAttributes()
	if logAttrs.Attributes != nil {
		for k, v := range logAttrs.Attributes {
			attrs[k] = v
		}
	}
	if logAttrs.Host != nil {
		attrs["host"] = *logAttrs.Host
	}
	if logAttrs.Service != nil {
		attrs["service"] = *logAttrs.Service
	}
	if logAttrs.Status != nil {
		attrs["status"] = *logAttrs.Status
	}
	if logAttrs.Message != nil {
		attrs["message"] = *logAttrs.Message
	}
	var ts time.Time
	if logAttrs.Timestamp != nil {
		ts = *logAttrs.Timestamp
	}
	raw, _ := json.Marshal(ddLog)
	return matchers.ThreatestEvent{
		EventName:  "log",
		Time:       ts,
		Attributes: attrs,
		Body:       raw,
	}
}
