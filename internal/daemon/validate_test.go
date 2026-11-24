package daemon

import (
	"slices"
	"strings"
	"testing"
)

func TestValidators(t *testing.T) {
	tests := []struct {
		name string
		err  error
		ok   bool
	}{
		{"argv ok", validateArgv([]string{"sh", "-c", "echo hi"}), true},
		{"argv empty", validateArgv(nil), false},
		{"argv too many", validateArgv(make([]string, maxArgs+1)), false},
		{"argv too big", validateArgv([]string{strings.Repeat("a", maxArgBytes+1)}), false},
		{"env ok", validateEnv([]string{"A=1", "_B=", "C_9=x=y"}), true},
		{"env no equals", validateEnv([]string{"A"}), false},
		{"env bad key", validateEnv([]string{"1A=x"}), false},
		{"env nul", validateEnv([]string{"A=\x00"}), false},
		{"workdir empty", validateWorkdir(""), true},
		{"workdir abs", validateWorkdir("/src/app"), true},
		{"workdir rel", validateWorkdir("src"), false},
		{"workdir unclean", validateWorkdir("/src/../etc"), false},
		{"workdir trailing slash", validateWorkdir("/src/"), false},
		{"hostname ok", validateHostname("qt-1a2b"), true},
		{"hostname upper", validateHostname("QT"), false},
		{"hostname dash end", validateHostname("qt-"), false},
		{"labels ok", validateLabels(map[string]string{"app.kubernetes.io/name": "x"}), true},
		{"labels key", validateLabels(map[string]string{"-x": "y"}), false},
	}
	for _, tt := range tests {
		if (tt.err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok=%v", tt.name, tt.err, tt.ok)
		}
	}
}

func TestMergeEnv(t *testing.T) {
	got := mergeEnv([]string{"PATH=/bin", "A=1"}, "A=2", "B=3")
	if !slices.Equal(got, []string{"PATH=/bin", "A=2", "B=3"}) {
		t.Errorf("mergeEnv = %v", got)
	}
}
