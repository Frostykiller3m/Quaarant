package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

// fakeEnv is a configurable Env. The zero value is a Linux host with nothing installed.
type fakeEnv struct {
	goos       string
	kvmVersion int
	kvmErr     error
	bins       map[string]string // name -> version output
	cgMounted  bool
	cgCtrls    []string
	cgErr      error
	reflinkOK  bool
	reflinkFS  string
	reflinkErr error
}

func (f fakeEnv) OS() (string, string, string) {
	goos := f.goos
	if goos == "" {
		goos = "linux"
	}
	return goos, "amd64", "6.8.0-qt"
}

func (f fakeEnv) KVMAPIVersion() (int, error) { return f.kvmVersion, f.kvmErr }

func (f fakeEnv) LookPath(name string) (string, error) {
	if _, ok := f.bins[name]; ok {
		return "/usr/bin/" + name, nil
	}
	return "", fmt.Errorf("%s: %w", name, fs.ErrNotExist)
}

func (f fakeEnv) Output(_ context.Context, name string, _ ...string) (string, error) {
	out, ok := f.bins[name]
	if !ok || out == "" {
		return "", errors.New("exit status 1")
	}
	return out, nil
}

func (f fakeEnv) Cgroup2() (bool, []string, error) { return f.cgMounted, f.cgCtrls, f.cgErr }

func (f fakeEnv) Reflink(dir string) (string, string, bool, error) {
	return dir, f.reflinkFS, f.reflinkOK, f.reflinkErr
}

// fullHost has everything.
func fullHost() fakeEnv {
	return fakeEnv{
		kvmVersion: 12,
		bins: map[string]string{
			"firecracker": "Firecracker v1.12.0\n\nSupported snapshot data format versions: ...",
			"jailer":      "Jailer v1.12.0",
			"runsc":       "runsc version release-20261110.0\nspec: 1.1.0-rc.1",
			"nft":         "nftables v1.0.9 (Old Doc Yak #3)",
			"ip":          "ip utility, iproute2-6.1.0",
		},
		cgMounted: true, cgCtrls: []string{"cpuset", "cpu", "io", "memory", "hugetlb", "pids", "rdma"},
		reflinkOK: true, reflinkFS: "btrfs",
	}
}

func without(f fakeEnv, bins ...string) fakeEnv {
	m := map[string]string{}
	for k, v := range f.bins {
		m[k] = v
	}
	for _, b := range bins {
		delete(m, b)
	}
	f.bins = m
	return f
}

func TestRun(t *testing.T) {
	permErr := &fs.PathError{Op: "open", Path: "/dev/kvm", Err: fs.ErrPermission}
	noentErr := &fs.PathError{Op: "open", Path: "/dev/kvm", Err: fs.ErrNotExist}

	tests := []struct {
		name     string
		env      fakeEnv
		wantRec  backend.Isolation
		want     map[string]Status
		wantText []string // substrings of the rendered table
	}{
		{
			name: "everything available", env: fullHost(), wantRec: backend.IsolationVM,
			want: map[string]Status{CheckOS: OK, CheckKVM: OK, CheckFirecracker: OK, CheckRunsc: OK, CheckCgroup: OK, CheckNftables: OK, CheckReflink: OK},
			wantText: []string{
				"API version 12", "Firecracker v1.12.0", "runsc version release-20261110.0",
				"cgroup2 with cpu, memory, pids", "reflink supported on /data (btrfs)", "--isolation=vm",
			},
		},
		{
			name: "no kvm device (WSL2 without nested virt)",
			env:  func() fakeEnv { f := fullHost(); f.kvmErr = noentErr; return f }(), wantRec: backend.IsolationGVisor,
			want:     map[string]Status{CheckKVM: Fail, CheckRunsc: OK},
			wantText: []string{"/dev/kvm not found", "nestedVirtualization=true", "--isolation=gvisor", "KVM is not"},
		},
		{
			name: "kvm permission denied",
			env:  func() fakeEnv { f := fullHost(); f.kvmErr = permErr; return f }(), wantRec: backend.IsolationGVisor,
			want:     map[string]Status{CheckKVM: Fail},
			wantText: []string{"permission denied", "usermod -aG kvm"},
		},
		{
			name: "wrong kvm api version",
			env:  func() fakeEnv { f := fullHost(); f.kvmVersion = 11; return f }(), wantRec: backend.IsolationGVisor,
			want: map[string]Status{CheckKVM: Fail}, wantText: []string{"unexpected KVM API version 11"},
		},
		{
			name: "kvm but no firecracker", env: without(fullHost(), "jailer"), wantRec: backend.IsolationGVisor,
			want:     map[string]Status{CheckKVM: OK, CheckFirecracker: Fail},
			wantText: []string{"not found: jailer", "install firecracker to enable --isolation=vm"},
		},
		{
			name: "only firecracker", env: without(fullHost(), "runsc"), wantRec: backend.IsolationVM,
			want: map[string]Status{CheckRunsc: Fail},
		},
		{
			name: "cgroup v1 blocks everything",
			env:  func() fakeEnv { f := fullHost(); f.cgMounted = false; return f }(), wantRec: "",
			want:     map[string]Status{CheckCgroup: Fail},
			wantText: []string{"not cgroup2", "No isolation level is usable", "cgroup v2"},
		},
		{
			name: "cgroup missing pids controller",
			env:  func() fakeEnv { f := fullHost(); f.cgCtrls = []string{"cpu", "memory"}; return f }(), wantRec: "",
			want: map[string]Status{CheckCgroup: Fail}, wantText: []string{"missing controllers: pids"},
		},
		{
			name: "nft without iproute2",
			env:  func() fakeEnv { f := fullHost(); delete(f.bins, "ip"); return f }(), wantRec: "vm",
			want: map[string]Status{CheckNftables: Warn}, wantText: []string{"ip not found", "apt install iproute2"},
		},
		{
			name: "cgroup unreadable",
			env:  func() fakeEnv { f := fullHost(); f.cgErr = errors.New("statfs: no such file"); return f }(), wantRec: "",
			want: map[string]Status{CheckCgroup: Fail},
		},
		{
			name: "nothing installed", env: fakeEnv{cgMounted: true, cgCtrls: RequiredControllers, kvmErr: noentErr, reflinkFS: "ext4"},
			wantRec:  "",
			want:     map[string]Status{CheckRunsc: Fail, CheckFirecracker: Fail, CheckNftables: Warn, CheckReflink: Warn},
			wantText: []string{"install gVisor", "apt install nftables", "no reflink on /data (ext4)"},
		},
		{
			name: "reflink untestable is only a warning",
			env:  func() fakeEnv { f := fullHost(); f.reflinkOK = false; f.reflinkErr = fs.ErrPermission; return f }(), wantRec: backend.IsolationVM,
			want: map[string]Status{CheckReflink: Warn}, wantText: []string{"could not test /data (btrfs)", "--data-dir"},
		},
		{
			name: "version command fails", env: func() fakeEnv { f := fullHost(); f.bins["runsc"] = ""; return f }(), wantRec: backend.IsolationVM,
			want: map[string]Status{CheckRunsc: OK}, wantText: []string{"runsc found (version unknown)"},
		},
		{
			name: "not linux", env: fakeEnv{goos: "windows"}, wantRec: "",
			want:     map[string]Status{CheckOS: Fail, CheckKVM: Skip, CheckRunsc: Skip, CheckReflink: Skip},
			wantText: []string{"windows/amd64", "WSL2", "this OS cannot run sandboxes"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rep := Run(context.Background(), tt.env, "/data")
			if rep.Recommendation != tt.wantRec {
				t.Errorf("recommendation = %q, want %q (%s)", rep.Recommendation, tt.wantRec, rep.Reason)
			}
			if len(rep.Results) != 7 {
				t.Errorf("got %d checks, want 7", len(rep.Results))
			}
			for name, want := range tt.want {
				got, ok := rep.Get(name)
				if !ok || got.Status != want {
					t.Errorf("%s: got %+v, want status %s", name, got, want)
				}
			}
			var buf bytes.Buffer
			if err := rep.WriteTable(&buf); err != nil {
				t.Fatal(err)
			}
			for _, s := range tt.wantText {
				if !strings.Contains(buf.String(), s) {
					t.Errorf("table missing %q:\n%s", s, buf.String())
				}
			}
		})
	}
}

func TestVersionLineTruncated(t *testing.T) {
	f := fullHost()
	f.bins["nft"] = strings.Repeat("v", 200)
	r, _ := Run(context.Background(), f, "/data").Get(CheckNftables)
	if len([]rune(r.Detail)) != 81 {
		t.Fatalf("detail not truncated to 80+…: %d runes", len([]rune(r.Detail)))
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Run(context.Background(), fullHost(), "/data").WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Checks []Result `json:"checks"`
		Rec    string   `json:"recommendation"`
	}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Rec != "vm" || len(got.Checks) != 7 || got.Checks[1].Name != CheckKVM {
		t.Fatalf("unexpected JSON: %s", buf.String())
	}
}

func TestNearestExisting(t *testing.T) {
	dir := t.TempDir()
	got, err := nearestExisting(filepath.Join(dir, "a", "b", "c"))
	if err != nil || got != dir {
		t.Fatalf("nearestExisting = %q, %v; want %q", got, err, dir)
	}
	f := filepath.Join(dir, "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := nearestExisting(f); got != f {
		t.Fatalf("existing path: got %q", got)
	}
}

// TestSystemEnv exercises the real host probes. It only asserts what holds everywhere; on Linux
// CI it also checks that the probes return without crashing and that reflink is testable in a
// temp dir.
func TestSystemEnv(t *testing.T) {
	env := SystemEnv()
	rep := Run(context.Background(), env, t.TempDir())
	if len(rep.Results) != 7 {
		t.Fatalf("got %d checks", len(rep.Results))
	}
	var buf bytes.Buffer
	_ = rep.WriteTable(&buf)
	t.Logf("doctor on this host:\n%s", buf.String())
	if goos, _, _ := env.OS(); goos == "linux" {
		if r, _ := rep.Get(CheckReflink); strings.HasPrefix(r.Detail, "could not test") {
			t.Errorf("reflink probe failed in a writable temp dir: %s", r.Detail)
		}
	}
}
