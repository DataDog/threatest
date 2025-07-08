package api

import "net/http"

// SplunkAPI defines the interface for Splunk operations
type SplunkAPI interface {
	SearchNotables(filter map[string]string) ([]map[string]interface{}, error)
	CloseNotable(id string) error
}

// TokenTransport adds auth token to all requests
type TokenTransport struct {
	token   string
	wrapped http.RoundTripper
}

func (t *TokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.wrapped.RoundTrip(req)
}
