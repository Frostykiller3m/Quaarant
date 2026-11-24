package daemon

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Request bounds. Everything in a request is checked before it reaches a backend; the
// daemon is root and its callers are not.
const (
	maxArgs       = 4096
	maxArgBytes   = 1 << 20 // total argv or env bytes
	maxEnvVars    = 1024
	maxLabels     = 32
	maxLabelValue = 256
	maxPathLen    = 4096
	execChunk     = 32 << 10 // stdout/stderr bytes per ExecResponse
)

var (
	envKeyRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,255}$`)
	hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	labelKeyRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,62}$`)
)

func validateArgv(argv []string) error {
	if len(argv) == 0 {
		return fmt.Errorf("argv is empty")
	}
	if len(argv) > maxArgs {
		return fmt.Errorf("argv has %d entries (max %d)", len(argv), maxArgs)
	}
	total := 0
	for _, a := range argv {
		if strings.ContainsRune(a, 0) {
			return fmt.Errorf("argv contains a NUL byte")
		}
		total += len(a)
	}
	if total > maxArgBytes {
		return fmt.Errorf("argv is %d bytes (max %d)", total, maxArgBytes)
	}
	return nil
}

func validateEnv(env []string) error {
	if len(env) > maxEnvVars {
		return fmt.Errorf("env has %d entries (max %d)", len(env), maxEnvVars)
	}
	total := 0
	for _, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || !envKeyRe.MatchString(k) {
			return fmt.Errorf("env entry %.40q must be KEY=VALUE", kv)
		}
		if strings.ContainsRune(kv, 0) {
			return fmt.Errorf("env entry %.40q contains a NUL byte", k)
		}
		total += len(kv)
	}
	if total > maxArgBytes {
		return fmt.Errorf("env is %d bytes (max %d)", total, maxArgBytes)
	}
	return nil
}

// validateWorkdir accepts "" or a clean absolute path.
func validateWorkdir(w string) error {
	if w == "" {
		return nil
	}
	if len(w) > maxPathLen || !path.IsAbs(w) || path.Clean(w) != w || strings.ContainsRune(w, 0) {
		return fmt.Errorf("workdir %.64q must be a clean absolute path", w)
	}
	return nil
}

func validateHostname(h string) error {
	if h != "" && !hostnameRe.MatchString(h) {
		return fmt.Errorf("hostname %.64q must be a lowercase DNS label", h)
	}
	return nil
}

func validateLabels(l map[string]string) error {
	if len(l) > maxLabels {
		return fmt.Errorf("%d labels (max %d)", len(l), maxLabels)
	}
	for k, v := range l {
		if !labelKeyRe.MatchString(k) {
			return fmt.Errorf("label key %.64q is invalid", k)
		}
		if len(v) > maxLabelValue || strings.ContainsAny(v, "\x00\n") {
			return fmt.Errorf("label %s: value too long or has control characters", k)
		}
	}
	return nil
}

// mergeEnv applies over on top of base (later keys win), keeping first-seen order.
func mergeEnv(base []string, over ...string) []string {
	idx := map[string]int{}
	var out []string
	for _, kv := range append(append([]string{}, base...), over...) {
		k, _, _ := strings.Cut(kv, "=")
		if i, ok := idx[k]; ok {
			out[i] = kv
			continue
		}
		idx[k] = len(out)
		out = append(out, kv)
	}
	return out
}

func hasEnv(env []string, key string) bool {
	for _, kv := range env {
		if k, _, _ := strings.Cut(kv, "="); k == key {
			return true
		}
	}
	return false
}
