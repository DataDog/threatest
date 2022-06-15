package e2e

type AlertGeneratedAssertion interface {
	HasExpectedAlert(uid string) (bool, error)
	Cleanup(uuid string) error
}
