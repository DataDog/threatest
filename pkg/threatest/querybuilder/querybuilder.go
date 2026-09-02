package querybuilder

import (
	"bytes"
	"text/template"

	log "github.com/sirupsen/logrus"
)

type CorrelationVars struct {
	CorrelationID string
}

// SubstituteQuery resolves <% .CorrelationID %> markers in s using vars.
// Parse or execute errors leave s unchanged and log the cause, so typos
// surface as literal markers rather than aborting a detonation.
//
// The non-default <% %> delimiters avoid YAML parsers treating [[ ]] as flow
// sequences and editors splitting {{ }} into "{ {" on save.
func SubstituteQuery(s string, vars CorrelationVars) string {
	tmpl, err := template.New("").Delims("<%", "%>").Parse(s)
	if err != nil {
		log.Warnf("query substitution: parse %q: %v", s, err)
		return s
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		log.Warnf("query substitution: execute %q: %v", s, err)
		return s
	}
	return buf.String()
}
