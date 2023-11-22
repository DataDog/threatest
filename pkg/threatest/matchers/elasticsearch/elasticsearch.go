package elasticsearch

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

	es "github.com/elastic/go-elasticsearch/v8"
	"github.com/aws/smithy-go/ptr"
)

func (m *ElasticsearchAlertGeneratedAssertion) HasExpectedAlert(detonationUuid string) (bool, error) {
	// Construct the query necessary to find the alert
	query := `{ "query": { "match_all": {} } }`
	m.AlertAPI.Search(
		m.AlertAPI.Search.WithIndex(".siem-signals-*"),
		m.AlertAPI.Search.WithBody(strings.NewReader(query)),
	)
	// Alternative way of doing the same thing?
	res, err := m.AlertAPI.Search().
		Index(".siem-signals-*"). 
		Request(&search.Request{ 
			Query: &types.Query{
				Match: map[string]types.MatchQuery{
					"name": {Query: detonationUuid}, 
				},
			},
		}).Do(context.Background())

	search.Request{
		Query: &types.Query{
			Term: map[string]types.TermQuery{
				"rule": {Value: m.AlertFilter.RuleName},
				"uuid": 
			},
		},
	}

	return false, nil
}

func (m *ElasticsearchAlertGeneratedAssertion) String() string {
	return fmt.Sprintf("Elasticsearch alert '%s'", m.AlertFilter.Rule)
}

func (m *ElasticsearchAlertGeneratedAssertion) Cleanup(detonationUuid string) error {
	signals, err := m.SignalsAPI.SearchSignals(QueryAllOpenSignals)
	if err != nil {
		return errors.New("unable to search for Datadog security monitoring signals: " + err.Error())
	}

	for i := range signals {
		if m.signalMatchesExecution(signals[i], detonationUuid) {
			if err := m.SignalsAPI.CloseSignal(*signals[i].Id); err != nil {
				return errors.New("unable to archive signal " + *signals[i].Id + ": " + err.Error())
			}
		}
	}

	return nil
}