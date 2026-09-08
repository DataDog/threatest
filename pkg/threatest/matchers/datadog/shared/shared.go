package shared

import (
	"context"
	"fmt"
	"os"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/datadog/threatest/pkg/threatest/secret"
)

func GetDDSite() string {
	if ddSite, isSet := os.LookupEnv("DD_SITE"); isSet {
		return ddSite
	}
	return "datadoghq.com"
}

type APICredentials struct {
	APIKey secret.Secret
	AppKey secret.Secret
	Site   string
}

func NewCredentials(apiKey, appKey, site string) APICredentials {
	return APICredentials{
		APIKey: secret.New(apiKey),
		AppKey: secret.New(appKey),
		Site:   site,
	}
}

func CredentialsFromEnv() APICredentials {
	return NewCredentials(
		os.Getenv("DD_API_KEY"),
		os.Getenv("DD_APP_KEY"),
		GetDDSite(),
	)
}

func (c APICredentials) BuildContext(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, datadog.ContextAPIKeys, map[string]datadog.APIKey{
		"apiKeyAuth": {Key: c.APIKey.Value()},
		"appKeyAuth": {Key: c.AppKey.Value()},
	})
	ctx = context.WithValue(ctx, datadog.ContextServerVariables, map[string]string{
		"site": c.Site,
	})
	return ctx
}

func (c APICredentials) APIBaseURL() string {
	return fmt.Sprintf("https://api.%s", c.Site)
}
