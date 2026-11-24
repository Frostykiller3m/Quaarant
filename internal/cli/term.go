package cli

import (
	"os"
	"regexp"
)

var termRe = regexp.MustCompile(`^[a-zA-Z0-9._+-]{1,64}$`)

// termName is the TERM passed to sandbox terminals: the local one if sane, else xterm.
func termName() string {
	if t := os.Getenv("TERM"); termRe.MatchString(t) && t != "dumb" {
		return t
	}
	return "xterm"
}
