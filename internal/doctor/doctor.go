// Package doctor checks whether this host can run quarantine sandboxes and which --isolation
// level to recommend. All host access goes through Env so checks are testable with fakes.
package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

// Status of one check.
type Status string

// Check statuses.
const (
	OK   Status = "ok"
	Warn Status = "warn" // works, degraded
	Fail Status = "fail" // missing; blocks some isolation level
	Skip Status = "skip" // not applicable on this host
)

// Check names.
const (
	CheckOS          = "os"
	CheckKVM         = "kvm"
	CheckFirecracker = "firecracker"
	CheckRunsc       = "runsc"
	CheckCgroup      = "cgroup v2"
	CheckNftables    = "nftables"
	CheckReflink     = "reflink"
)

// KVMAPIVersion is the only KVM API version Linux has ever shipped (KVM_GET_API_VERSION).
const KVMAPIVersion = 12

// RequiredControllers are the cgroup v2 controllers sandboxes are limited with.
var RequiredControllers = []string{"cpu", "memory", "pids"}

// Env is the host as the checks see it.
type Env interface {
	// OS returns GOOS/GOARCH and, on Linux, the kernel release.
	OS() (goos, arch, kernel string)
	// KVMAPIVersion opens /dev/kvm read-write and returns KVM_GET_API_VERSION.
	KVMAPIVersion() (int, error)
	// LookPath finds an executable in PATH.
	LookPath(name string) (string, error)
	// Output runs a command and returns its combined output.
	Output(ctx context.Context, name string, args ...string) (string, error)
	// Cgroup2 reports whether /sys/fs/cgroup is cgroup2 and lists the enabled controllers.
	Cgroup2() (mounted bool, controllers []string, err error)
	// Reflink tries an FICLONE between two temp files in dir and names the filesystem.
	// It returns the directory actually tested (dir or its nearest existing parent).
	Reflink(dir string) (tested, fsType string, supported bool, err error)
}

// Result of one check.
type Result struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
	Hint   string `json:"hint,omitempty"`
}

// Report is the outcome of Run.
type Report struct {
	Results        []Result          `json:"checks"`
	Recommendation backend.Isolation `json:"recommendation,omitempty"`
	Reason         string            `json:"reason"`
}

// Usable reports whether at least one isolation level can run.
func (r Report) Usable() bool { return r.Recommendation != "" }

// Get returns the result for a check name.
func (r Report) Get(name string) (Result, bool) {
	i := slices.IndexFunc(r.Results, func(x Result) bool { return x.Name == name })
	if i < 0 {
		return Result{}, false
	}
	return r.Results[i], true
}

// Run performs every check against env. dataDir is where sandboxes will live.
func Run(ctx context.Context, env Env, dataDir string) Report {
	var rep Report
	add := func(r Result) { rep.Results = append(rep.Results, r) }

	goos, arch, kernel := env.OS()
	if goos != "linux" {
		add(Result{
			Name: CheckOS, Status: Fail, Detail: goos + "/" + arch,
			Hint: "sandboxes need Linux; on Windows run qt inside WSL2 (Ubuntu 24.04)",
		})
		for _, n := range []string{CheckKVM, CheckFirecracker, CheckRunsc, CheckCgroup, CheckNftables, CheckReflink} {
			add(Result{Name: n, Status: Skip, Detail: "not Linux"})
		}
		rep.Reason = "this OS cannot run sandboxes"
		return rep
	}
	add(Result{Name: CheckOS, Status: OK, Detail: fmt.Sprintf("linux/%s, kernel %s", arch, kernel)})
	add(checkKVM(env))
	add(checkFirecracker(ctx, env))
	add(checkRunsc(ctx, env))
	add(checkCgroup(env))
	add(checkNftables(ctx, env))
	add(checkReflink(env, dataDir))
	rep.Recommendation, rep.Reason = recommend(rep)
	return rep
}

func checkKVM(env Env) Result {
	r := Result{Name: CheckKVM}
	v, err := env.KVMAPIVersion()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		r.Status, r.Detail = Fail, "/dev/kvm not found"
		r.Hint = "enable virtualization in firmware; in WSL2 set nestedVirtualization=true in .wslconfig"
	case errors.Is(err, fs.ErrPermission):
		r.Status, r.Detail = Fail, "/dev/kvm: permission denied"
		r.Hint = "add yourself to the kvm group: sudo usermod -aG kvm $USER (then log in again)"
	case err != nil:
		r.Status, r.Detail = Fail, "/dev/kvm: "+err.Error()
	case v != KVMAPIVersion:
		r.Status, r.Detail = Fail, fmt.Sprintf("unexpected KVM API version %d (want %d)", v, KVMAPIVersion)
	default:
		r.Status, r.Detail = OK, fmt.Sprintf("/dev/kvm usable, API version %d", v)
	}
	return r
}

func checkFirecracker(ctx context.Context, env Env) Result {
	r := Result{Name: CheckFirecracker}
	var missing []string
	for _, bin := range []string{"firecracker", "jailer"} {
		if _, err := env.LookPath(bin); err != nil {
			missing = append(missing, bin)
		}
	}
	if len(missing) > 0 {
		r.Status, r.Detail = Fail, "not found: "+strings.Join(missing, ", ")
		r.Hint = "install firecracker and jailer from github.com/firecracker-microvm/firecracker/releases"
		return r
	}
	r.Status, r.Detail = OK, versionLine(ctx, env, "firecracker", "--version")
	return r
}

func checkRunsc(ctx context.Context, env Env) Result {
	r := Result{Name: CheckRunsc}
	if _, err := env.LookPath("runsc"); err != nil {
		r.Status, r.Detail = Fail, "runsc not found in PATH"
		r.Hint = "install gVisor: https://gvisor.dev/docs/user_guide/install/"
		return r
	}
	r.Status, r.Detail = OK, versionLine(ctx, env, "runsc", "--version")
	return r
}

func checkCgroup(env Env) Result {
	r := Result{Name: CheckCgroup}
	mounted, ctrls, err := env.Cgroup2()
	switch {
	case err != nil:
		r.Status, r.Detail = Fail, "cannot inspect /sys/fs/cgroup: "+err.Error()
		return r
	case !mounted:
		r.Status, r.Detail = Fail, "/sys/fs/cgroup is not cgroup2 (legacy v1 or hybrid)"
		r.Hint = "boot with systemd.unified_cgroup_hierarchy=1 (WSL2: kernelCommandLine in .wslconfig)"
		return r
	}
	var missing []string
	for _, c := range RequiredControllers {
		if !slices.Contains(ctrls, c) {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		r.Status, r.Detail = Fail, "cgroup2 is missing controllers: "+strings.Join(missing, ", ")
		r.Hint = "enable them in cgroup.subtree_control (qtd runs as a systemd service with Delegate=yes)"
		return r
	}
	r.Status, r.Detail = OK, "cgroup2 with "+strings.Join(RequiredControllers, ", ")
	return r
}

func checkNftables(ctx context.Context, env Env) Result {
	r := Result{Name: CheckNftables}
	if _, err := env.LookPath("nft"); err != nil {
		r.Status, r.Detail = Warn, "nft not found"
		r.Hint = "install nftables (apt install nftables); needed for --net=allow and --net=log"
		return r
	}
	if _, err := env.LookPath("ip"); err != nil { // sandbox links: netns, veth, routes
		r.Status, r.Detail = Warn, "ip not found"
		r.Hint = "install iproute2 (apt install iproute2); needed for --net=allow and --net=log"
		return r
	}
	r.Status, r.Detail = OK, versionLine(ctx, env, "nft", "--version")
	return r
}

func checkReflink(env Env, dataDir string) Result {
	r := Result{Name: CheckReflink}
	tested, fsType, ok, err := env.Reflink(dataDir)
	where := tested
	if fsType != "" {
		where += " (" + fsType + ")"
	}
	switch {
	case err != nil:
		r.Status, r.Detail = Warn, "could not test "+where+": "+err.Error()
		r.Hint = "run as root or pass --data-dir to a writable directory"
	case !ok:
		r.Status, r.Detail = Warn, "no reflink on "+where+"; copy-on-write falls back to full copies / dm-thin"
		r.Hint = "put the data dir on btrfs or xfs (reflink=1) for fast sandbox creation"
	default:
		r.Status, r.Detail = OK, "reflink supported on "+where
	}
	return r
}

// versionLine runs `bin args...` and returns the first output line, or a short note.
func versionLine(ctx context.Context, env Env, bin string, args ...string) string {
	out, err := env.Output(ctx, bin, args...)
	if err != nil {
		return bin + " found (version unknown)"
	}
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	const maxLen = 80
	if len(line) > maxLen {
		line = line[:maxLen] + "…"
	}
	return line
}

func recommend(rep Report) (backend.Isolation, string) {
	is := func(name string, want Status) bool {
		r, ok := rep.Get(name)
		return ok && r.Status == want
	}
	cgroupOK := is(CheckCgroup, OK)
	vmOK := is(CheckKVM, OK) && is(CheckFirecracker, OK) && cgroupOK
	gvisorOK := is(CheckRunsc, OK) && cgroupOK
	switch {
	case vmOK:
		return backend.IsolationVM, "KVM and firecracker are available: microVMs give the strongest isolation"
	case gvisorOK && is(CheckKVM, OK):
		return backend.IsolationGVisor, "runsc is available; install firecracker to enable --isolation=vm"
	case gvisorOK:
		return backend.IsolationGVisor, "runsc is available but KVM is not, so vm isolation is unavailable"
	case !cgroupOK:
		return "", "cgroup v2 with cpu, memory and pids is required for every isolation level"
	default:
		return "", "install gVisor (runsc), or firecracker on a host with KVM"
	}
}

// WriteTable renders the report for humans.
func (r Report) WriteTable(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CHECK\tSTATUS\tDETAIL")
	for _, res := range r.Results {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", res.Name, res.Status, res.Detail)
		if res.Hint != "" && (res.Status == Fail || res.Status == Warn) {
			fmt.Fprintf(tw, "\t\t↳ %s\n", res.Hint)
		}
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write table: %w", err)
	}
	if r.Usable() {
		_, err := fmt.Fprintf(w, "\nRecommendation: --isolation=%s (%s)\n", r.Recommendation, r.Reason)
		return err
	}
	_, err := fmt.Fprintf(w, "\nNo isolation level is usable: %s\n", r.Reason)
	return err
}

// WriteJSON renders the report as JSON.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}
