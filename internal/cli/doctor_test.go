package cli

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/qt-dev/quarantine/internal/doctor"
)

// stubEnv is a Linux host where only gVisor is usable.
type stubEnv struct{ dataDir *string }

func (stubEnv) OS() (string, string, string) { return "linux", "amd64", "6.8.0" }
func (stubEnv) KVMAPIVersion() (int, error)  { return 0, errors.New("no kvm") }
func (stubEnv) Cgroup2() (bool, []string, error) {
	return true, doctor.RequiredControllers, nil
}

func (stubEnv) LookPath(name string) (string, error) {
	if name == "runsc" {
		return "/usr/local/bin/runsc", nil
	}
	return "", errors.New("not found")
}

func (stubEnv) Output(context.Context, string, ...string) (string, error) {
	return "runsc version test", nil
}

func (s stubEnv) Reflink(dir string) (string, string, bool, error) {
	*s.dataDir = dir
	return dir, "xfs", true, nil
}

func useEnv(t *testing.T, env doctor.Env) {
	t.Helper()
	old := newDoctorEnv
	t.Cleanup(func() { newDoctorEnv = old })
	newDoctorEnv = func() doctor.Env { return env }
}

func TestDoctorCommand(t *testing.T) {
	var gotDir string
	useEnv(t, stubEnv{dataDir: &gotDir})

	out, err := run(t, "doctor")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CHECK", "runsc version test", "--isolation=gvisor", "kvm"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if gotDir != DefaultDataDir {
		t.Errorf("tested %q, want default data dir", gotDir)
	}

	out, err = run(t, "doctor", "--json", "--data-dir", "/srv/qt")
	if err != nil {
		t.Fatal(err)
	}
	var rep doctor.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if rep.Recommendation != "gvisor" || gotDir != "/srv/qt" {
		t.Errorf("recommendation %q, data dir %q", rep.Recommendation, gotDir)
	}
}

type windowsEnv struct{ stubEnv }

func (windowsEnv) OS() (string, string, string) { return "windows", "amd64", "" }

func TestDoctorFailsWhenUnusable(t *testing.T) {
	var d string
	useEnv(t, windowsEnv{stubEnv{dataDir: &d}})
	out, err := run(t, "doctor")
	if !errors.Is(err, errNoIsolation) {
		t.Fatalf("got %v, want errNoIsolation", err)
	}
	if !strings.Contains(out, "WSL2") {
		t.Errorf("expected WSL2 hint:\n%s", out)
	}
}
