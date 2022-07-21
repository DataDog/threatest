package detonators

import (
	"fmt"
	"gopkg.in/alessio/shellescape.v1"
)

func FormatCommand(rawCommand string, detonationUuid string) string {
	return fmt.Sprintf(
		`cp /bin/bash /tmp/%[1]s; (/tmp/%[1]s -c %[2]s || true) && rm /tmp/%[1]s`,
		detonationUuid, shellescape.Quote(rawCommand),
	)
}
