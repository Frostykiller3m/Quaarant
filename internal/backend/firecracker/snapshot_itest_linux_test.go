//go:build linux

package firecracker

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/netpol"
)

func thinVolumes(t *testing.T) int {
	t.Helper()
	out, _ := exec.Command("dmsetup", "ls").Output()
	n := 0
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "qt-pool-") && strings.Contains(strings.Fields(l + " x")[0], "-") && strings.Count(strings.Fields(l + " x")[0], "-") >= 3 {
			n++
		}
	}
	return n
}

// TestITestSnapshotFork: memory snapshots resume running processes in a new sandbox with a
// fresh identity; fork makes N independent copies, each with its own MAC, address, hostname,
// machine-id and RNG; disk-only snapshots keep files, not processes; nothing is left behind.
func TestITestSnapshotFork(t *testing.T) {
	v := setupVM(t)
	ctx := context.Background()
	n := rand.IntN(200)
	nm, err := netpol.New(ctx, netpol.Config{Tag: fmt.Sprintf("f%02x", n), Pool: netip.MustParsePrefix(fmt.Sprintf("10.236.%d.0/24", n)), ProxyPort: netpol.DefaultProxyPort, DNSPort: netpol.DefaultDNSPort})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nm.Close(context.Background()) })
	spec := func(id string) backend.Spec {
		l, err := nm.Attach(ctx, id, netpol.Tap, jailID(id), netpol.Rules{Mode: netpol.ModeLog}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = nm.Detach(context.Background(), id) })
		s := backend.Spec{
			ID: id, Image: v.Img.Ref, RootFS: v.Ext4, Workspace: filepath.Join(v.Data, "sb", id), Hostname: "qt-" + id,
			User: "65534:65534", Env: []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=/tmp"},
			Limits: backend.Limits{CPUMillis: 1000, MemoryBytes: 256 << 20, PIDs: 64}, Network: l.Network(), Events: nopSink{},
		}
		if err := os.MkdirAll(s.Workspace, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = v.B.Destroy(context.Background(), id) })
		return s
	}
	sh := func(id, script string) string {
		t.Helper()
		out, errs, st := v.exec(t, id, backend.ExecSpec{Argv: []string{"/bin/sh", "-c", script}})
		if st.Code != 0 {
			t.Fatalf("%s: %q: exit %d %q", id, script, st.Code, errs)
		}
		return strings.TrimSpace(out)
	}
	identity := "hostname; cat /sys/class/net/eth0/address; ip -4 addr show eth0 | awk '/inet /{print $2}'; cat /etc/machine-id; head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \\n'"

	before := thinVolumes(t)
	p := spec("parent")
	if err := v.B.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := v.B.Start(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	sh(p.ID, "echo parent-state > /tmp/state; setsid sleep 1000 </dev/null >/dev/null 2>&1 & echo $! > /tmp/sleeper")
	parentID := sh(p.ID, identity)

	snapDir := filepath.Join(v.Data, "snapshots", "s1")
	t0 := time.Now()
	ref, err := v.B.Snapshot(ctx, p.ID, backend.SnapshotOptions{Memory: true, Dir: snapDir})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("memory snapshot: %v", time.Since(t0).Round(time.Millisecond))
	t.Cleanup(func() { _ = v.B.DeleteSnapshot(context.Background(), ref) })
	if got := sh(p.ID, "cat /tmp/state; kill -0 $(cat /tmp/sleeper) && echo alive"); got != "parent-state\nalive" {
		t.Fatalf("parent after snapshot: %q", got)
	}

	t.Run("restore resumes processes, with a new identity", func(t *testing.T) {
		r := spec("restored")
		t0 := time.Now()
		if err := v.B.Restore(ctx, ref, r); err != nil {
			t.Fatal(err)
		}
		t.Logf("restore: %v", time.Since(t0).Round(time.Millisecond))
		if got := sh(r.ID, "cat /tmp/state; kill -0 $(cat /tmp/sleeper) && echo alive"); got != "parent-state\nalive" {
			t.Errorf("restored state: %q", got)
		}
		checkFresh(t, parentID, sh(r.ID, identity))
		if out := sh(r.ID, "wget -q -T 10 -O- http://example.com/ | head -c 15"); !strings.Contains(out, "<!doctype") {
			t.Errorf("restored VM's network: %q", out)
		}
	})

	t.Run("fork makes independent copies", func(t *testing.T) {
		var kids []backend.Spec
		for i := range 3 {
			kids = append(kids, spec(fmt.Sprintf("kid%d", i)))
		}
		t0 := time.Now()
		if err := v.B.Fork(ctx, p.ID, kids); err != nil {
			t.Fatal(err)
		}
		t.Logf("fork x3: %v", time.Since(t0).Round(time.Millisecond))
		ids := []string{parentID}
		for i, k := range kids {
			if got := sh(k.ID, "cat /tmp/state; kill -0 $(cat /tmp/sleeper) && echo alive"); got != "parent-state\nalive" {
				t.Errorf("%s: %q", k.ID, got)
			}
			sh(k.ID, fmt.Sprintf("echo kid%d > /tmp/state", i))
			id := sh(k.ID, identity)
			for _, other := range ids {
				checkFresh(t, other, id)
			}
			ids = append(ids, id)
		}
		for i, k := range kids {
			if got := sh(k.ID, "cat /tmp/state"); got != fmt.Sprintf("kid%d", i) {
				t.Errorf("%s sees %q: not independent", k.ID, got)
			}
		}
		if got := sh(p.ID, "cat /tmp/state; kill -0 $(cat /tmp/sleeper) && echo alive"); got != "parent-state\nalive" {
			t.Errorf("parent after fork: %q", got)
		}
		entries, err := os.ReadDir(filepath.Join(v.Data, "snapshots"))
		if err == nil {
			for _, e := range entries {
				if strings.HasPrefix(e.Name(), ".fork-") {
					t.Errorf("fork left its snapshot: %s", e.Name())
				}
			}
		}
		// Manifests: the guests list their filesystems; a child's change shows.
		sh(kids[0].ID, "echo new > /tmp/only-in-kid0")
		pm, err := v.B.Manifest(ctx, p.ID)
		if err != nil {
			t.Fatal(err)
		}
		km, err := v.B.Manifest(ctx, kids[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		has := func(es []backend.Entry, p string) bool {
			for _, e := range es {
				if e.Path == p {
					return true
				}
			}
			return false
		}
		if !has(km, "/tmp/only-in-kid0") || has(pm, "/tmp/only-in-kid0") || !has(pm, "/etc/os-release") || has(pm, "/.qt/qt-agent") {
			t.Errorf("manifests: %d and %d entries", len(pm), len(km))
		}
		t.Logf("manifest: %d entries", len(pm))
	})

	t.Run("disk-only snapshot keeps files, not processes", func(t *testing.T) {
		dref, err := v.B.Snapshot(ctx, p.ID, backend.SnapshotOptions{Dir: filepath.Join(v.Data, "snapshots", "s2")})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = v.B.DeleteSnapshot(context.Background(), dref) })
		d := spec("fromdisk")
		if err := v.B.Restore(ctx, dref, d); err != nil {
			t.Fatal(err)
		}
		if got := sh(d.ID, "cat /tmp/state; kill -0 $(cat /tmp/sleeper) 2>/dev/null && echo alive || echo gone"); got != "parent-state\ngone" {
			t.Errorf("from disk: %q", got)
		}
	})

	for _, id := range []string{"restored", "kid0", "kid1", "kid2", "fromdisk", "parent"} {
		_ = v.B.Destroy(ctx, id)
	}
	_ = v.B.DeleteSnapshot(ctx, ref)
	if after := thinVolumes(t); after > before {
		t.Errorf("thin volumes: %d before, %d after", before, after)
	}
}

// checkFresh: two sandboxes' identities (hostname, MAC, address, machine-id, 16 random
// bytes) share nothing.
func checkFresh(t *testing.T, a, b string) {
	t.Helper()
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	if len(al) != 5 || len(bl) != 5 {
		t.Fatalf("identity output: %q vs %q", a, b)
	}
	for i, what := range []string{"hostname", "MAC", "address", "machine-id", "urandom"} {
		if al[i] == bl[i] || bl[i] == "" {
			t.Errorf("%s not fresh: %q", what, bl[i])
		}
	}
}
