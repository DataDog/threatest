package elasticsearch

import (
	"os"
	"time"
	"github.com/cenkalti/backoff/v4"
	"strings"
	"fmt"

	log "github.com/sirupsen/logrus"
	es "github.com/elastic/go-elasticsearch/v8"
)

type ElasticsearchQueryResponse struct {
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
		} `json:"total"`
		Hits []ElasticsearchQueryHit `json:"hits"`
	} `json:"hits"`
}

type ElasticsearchQueryHit struct {
	Index  string                 `json:"_index"`
	ID     string                 `json:"_id"`
	Source map[string]interface{} `json:"_source"`
}

type ElasticsearchAlertFilter struct {
	RuleName  string `yaml:"rule-name"`
	UuidField string `yaml:"uuid-field"`
}

type ElasticsearchAlertGeneratedAssertion struct {
	AlertAPI    es.Client
	AlertFilter *ElasticsearchAlertFilter
	AlertId     string
	Index       string
}

func ElasticsearchAlert(ruleName, uuidField string) *ElasticsearchAlertGeneratedAssertion {
	retryBackoff := backoff.NewExponentialBackOff()
	// New Elasticsearch client
	esClient, err := es.NewClient(es.Config{
		Addresses: []string{os.Getenv("ELASTICSEARCH_URL")},
		Username:  os.Getenv("ELASTICSEARCH_USERNAME"),
		Password:  os.Getenv("ELASTICSEARCH_PASSWORD"),
		// Retry on 429 TooManyRequests statuses
		RetryOnStatus: []int{502, 503, 504, 429},
		// Configure the backoff function
		RetryBackoff: func(i int) time.Duration {
			if i == 1 {
				retryBackoff.Reset()
			}
			return retryBackoff.NextBackOff()
		},
		// Retry up to 5 attempts
		MaxRetries: 5,
	})
	if err != nil {
		log.Fatalf("failed to create Elasticsearch client: %w", err)
	}
	info, err := esClient.Info()
	if err != nil {
		log.Fatalf("failed to get Elasticsearch cluster info: %w", err)
	}
	log.Info("Elasticsearch cluster info:\n", info.String())
	return &ElasticsearchAlertGeneratedAssertion{
		AlertAPI:    *esClient,
		AlertFilter: &ElasticsearchAlertFilter{RuleName: ruleName, UuidField: uuidField},
	}
}


// Dumping Ground
func CreateIndex(m *ElasticsearchAlertGeneratedAssertion, index string) {
	mapping := `
    {
      "settings": {
        "number_of_shards": 1
      },
      "mappings": {
        "properties": {
          "field1": {
            "type": "text"
          },
		  "date": {
			"type": "date" 
		  }
        }
      }
    }`
	res, err := m.AlertAPI.Indices.Create(
        index,
        m.AlertAPI.Indices.Create.WithBody(strings.NewReader(mapping)),
    )
    if err != nil {
        log.Fatal(err)
    }
    log.Println(res)
}

func WriteToIndex(m *ElasticsearchAlertGeneratedAssertion, index string) {
	entry := `
	{
		"field1": "helloo there abc1234",
		"@timestamp": "%s"
	}`
	res, err := m.AlertAPI.Index(index, strings.NewReader(fmt.Sprintf(entry, time.Now().Format("2006/01/02 15:04:05"))))
	if err != nil {
		log.Fatal(err)
	}
	log.Println(res)
}
