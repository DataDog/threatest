package detonators

//TODO probably not a full struct needed
type OSLayerAttackTechnique struct {
	Command string
}

type CommandDetonator interface {
	RunCommand(command string) (string, error)
}

type CommandDetonatorImpl struct {
	Detonator CommandDetonator
	Technique *OSLayerAttackTechnique
}

func NewCommandDetonator(detonator CommandDetonator, command string) *CommandDetonatorImpl {
	return &CommandDetonatorImpl{
		Detonator: detonator,
		Technique: &OSLayerAttackTechnique{Command: command},
	}
}

func (m *CommandDetonatorImpl) Detonate() (string, error) {
	return m.Detonator.RunCommand(m.Technique.Command)
}
