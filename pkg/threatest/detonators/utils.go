package detonators

import (
	"fmt"
	"gopkg.in/alessio/shellescape.v1"
)

func FormatCommand(rawCommand string, detonationUuid string) string {
	return fmt.Sprintf(
		`export %[1]s=%[1]s; bash -c %[2]s || true`,
		detonationUuid, shellescape.Quote(rawCommand),
	)
}
