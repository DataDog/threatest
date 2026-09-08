package matchers

import (
	"context"
	"encoding/json"
	"time"
)

type ThreatestEvent struct {
	EventName  string          `json:"eventName"`
	Time       time.Time       `json:"time"`
	Attributes map[string]any  `json:"attributes"`
	Body       json.RawMessage `json:"body"`
}

type SearchOptions struct {
	From time.Time
	To   time.Time
}

type SearchOption func(*SearchOptions)

func WithTimeRange(from, to time.Time) SearchOption {
	return func(o *SearchOptions) {
		o.From = from
		o.To = to
	}
}

func ResolveOpts(opts []SearchOption) SearchOptions {
	o := SearchOptions{}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

type TelemetryMatcher interface {
	HasExpected(ctx context.Context, correlationID string) (bool, error)
	Related(ctx context.Context, correlationID string) (map[string]ThreatestEvent, error)
	Search(ctx context.Context, query string, opts ...SearchOption) (map[string]ThreatestEvent, error)
	String() string
	Cleanup(ctx context.Context, correlationID string) error
}
