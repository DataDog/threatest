// Package secret provides a string wrapper that redacts its value when logged
// or serialised. It is used to hold credentials (e.g. API keys) without
// risking accidental leaks through logs, error messages, or JSON output.
package secret

import "fmt"

// Secret holds a sensitive string value. Its String() and MarshalJSON()
// methods return a redacted placeholder to prevent accidental logging
// or serialisation of credentials.
//
// When Go's runtime/secret package graduates from experimental, this
// type should be replaced by runtime.Secret.
type Secret struct {
	value string
}

const redactedValue = "[REDACTED]"

// New wraps a sensitive string.
func New(value string) Secret {
	return Secret{value: value}
}

// Value returns the underlying secret. Use deliberately — not in logs.
func (s Secret) Value() string {
	return s.value
}

// String returns a redacted placeholder.
func (s Secret) String() string {
	return redactedValue
}

// GoString prevents fmt %#v from leaking the value.
func (s Secret) GoString() string {
	return redactedValue
}

// MarshalJSON returns a redacted JSON string.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redactedValue + `"`), nil
}

// MarshalText returns a redacted text representation.
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(redactedValue), nil
}

// Format catches all fmt verbs (%x, %q, etc.) to prevent leaks.
func (s Secret) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte(redactedValue))
}
