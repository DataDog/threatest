package matchers

type AlertGeneratedMatcher interface {
	HasExpectedAlert(uid string) (bool, error)
	String() string
	Cleanup(uuid string) error
}
