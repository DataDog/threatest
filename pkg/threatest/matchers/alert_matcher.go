package matchers

// AlertGeneratedMatcher is an interface that every integration should implement to verify whether an expected
// security alert was created
type AlertGeneratedMatcher interface {
	// HasExpectedAlert verifies on a third-party service whether an alert was properly generated for the given detonation UUID
	HasExpectedAlert(uuid string) (bool, error)

	// String returns the textual, user-friendly representation of the matcher
	String() string

	// Cleanup closes the generated alerts of a given detonation on a third-party service
	Cleanup(uuid string) error
}
