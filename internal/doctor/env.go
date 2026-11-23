package doctor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

// SystemEnv returns the Env for the real host.
func SystemEnv() Env { return systemEnv{} }

type systemEnv struct{}

func (systemEnv) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (systemEnv) Output(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// Callers only pass fixed binary names and flags (firecracker, runsc, nft --version).
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // G204: fixed commands, see above
	if err != nil {
		return string(out), fmt.Errorf("%s: %w", name, err)
	}
	return string(out), nil
}

func (systemEnv) OS() (string, string, string) {
	return runtime.GOOS, runtime.GOARCH, kernelRelease()
}

// nearestExisting returns dir, or its closest ancestor that exists, as an absolute path.
func nearestExisting(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return dir, fmt.Errorf("resolve %s: %w", dir, err)
	}
	for p := abs; ; p = filepath.Dir(p) {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return p, fmt.Errorf("stat %s: %w", p, err)
		}
		if filepath.Dir(p) == p {
			return p, fmt.Errorf("no existing parent of %s", abs)
		}
	}
}
