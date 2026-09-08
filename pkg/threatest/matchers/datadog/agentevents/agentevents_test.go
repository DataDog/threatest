package agentevents

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func sampleEvent(id, title, source string) map[string]any {
	return map[string]any{
		"id":     id,
		"title":  title,
		"source": source,
		"tags":   []string{"env:sandbox"},
	}
}

func TestConvertEvent(t *testing.T) {
	result := convertEvent(sampleEvent("evt-1", "detonation", "kubernetes"))
	assert.Equal(t, "detonation", result.Attributes["title"])
	assert.Equal(t, "kubernetes", result.Attributes["source"])
	assert.NotNil(t, result.Body)
}

func TestDefaultCorrelationQuery(t *testing.T) {
	m := &Matcher{Filter: &Filter{}}
	assert.Equal(t, "stratus-red-team", m.defaultCorrelationQuery())
}

func TestDefaultCorrelationQueryCustom(t *testing.T) {
	m := &Matcher{Filter: &Filter{Query: "source:k8s"}}
	assert.Equal(t, "source:k8s", m.defaultCorrelationQuery())
}
