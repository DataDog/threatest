package detonators

type Detonator interface {
	Detonate() (string, error)
}
