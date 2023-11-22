package elasticsearch

import (
	"context"
	"os"

	elasticsearch "github.com/elastic/go-elasticsearch/v8"
)

type ElasticsearchAlertFilter struct {
	RuleName string `yaml:"rule-name"`
}

type ElasticsearchAlertGeneratedAssertion struct {
	AlertAPI    ElasticsearchClient
	AlertFilter *ElasticsearchAlertFilter
}

func GetElasticSearchClient() (ElasticsearchClient, error) {
	// New Elasticsearch client
	cfg := elasticsearch.Config{
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
	}
	es, err := elasticsearch.NewTypedClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Elasticsearch client: %w", err)
	}
	info, err := es.Info().Do(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Elasticsearch cluster info: %w", err)
	}
	log.Info("Elasticsearch cluster info", "cluster_name", info.ClusterName, "version", info.Version.Number)
	return es, nil
}

func ElasticsearchAlert(rule, tellTale string) *ElasticsearchAlertGeneratedAssertion {
	es, err := GetElasticSearchClient()
	if err != nil {
		log.Error(err, "failed to create Elasticsearch client")
		return nil
	}
	return &ElasticsearchAlertGeneratedAssertion{
		AlertAPI:    es,
		AlertFilter: &ElasticsearchAlertFilter{RuleName: rule},
	}
}
