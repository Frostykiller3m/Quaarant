//go:build linux

package daemon

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/events"
)

func TestSnapshotRestoreFork(t *testing.T) {
	h := newHarness(t, backend.CapMemorySnapshot|backend.CapDiskSnapshot|backend.CapFork, nil)
	ctx := context.Background()
	src := h.create(t, &qtdv1.CreateRequest{Honeytokens: true, Labels: map[string]string{"team": "a"}})
	if err := h.be.CopyIn(ctx, src.GetId(), "/work/state", strings.NewReader("v1")); err != nil {
		t.Fatal(err)
	}

	snap, err := h.client.Snapshot(ctx, &qtdv1.SnapshotRequest{SandboxId: src.GetId(), Name: "before tests", IncludeMemory: true})
	if err != nil || !snap.GetIncludesMemory() || !strings.HasPrefix(snap.GetSnapshotId(), "sn-") {
		t.Fatalf("snapshot: %v %v", snap, err)
	}
	list, err := h.client.ListSnapshots(ctx, &qtdv1.ListSnapshotsRequest{})
	if err != nil || len(list.GetSnapshots()) != 1 || list.GetSnapshots()[0].GetSandboxId() != src.GetId() || list.GetSnapshots()[0].GetName() != "before tests" {
		t.Fatalf("list: %v %v", list, err)
	}
	if _, err := os.Stat(filepath.Join(h.data, "snapshots", snap.GetSnapshotId(), "honeytokens.json")); err != nil {
		t.Error("the snapshot does not keep the honeytokens")
	}

	// Restore: a new sandbox with the snapshot's state, its parent recorded, its own id.
	rr, err := h.client.Restore(ctx, &qtdv1.RestoreRequest{SnapshotId: snap.GetSnapshotId(), Labels: map[string]string{"run": "2"}})
	if err != nil {
		t.Fatal(err)
	}
	r := rr.GetSandbox()
	if r.GetId() == src.GetId() || r.GetParentId() != src.GetId() || r.GetLabels()["team"] != "a" || r.GetLabels()["run"] != "2" {
		t.Errorf("restored: %v", r)
	}
	var b bytes.Buffer
	if err := h.be.CopyOut(ctx, r.GetId(), "/work/state", &b); err != nil || b.String() != "v1" {
		t.Errorf("restored state: %q %v", b.String(), err)
	}
	if _, err := os.Stat(filepath.Join(h.data, "sandboxes", r.GetId(), "honeytokens.json")); err != nil {
		t.Error("the restored sandbox has no honeytokens record (its tokens are in the snapshot)")
	}

	// Fork: three children of the running source.
	fr, err := h.client.Fork(ctx, &qtdv1.ForkRequest{SandboxId: src.GetId(), Count: 3})
	if err != nil || len(fr.GetSandboxes()) != 3 {
		t.Fatalf("fork: %v %v", fr, err)
	}
	seen := map[string]bool{src.GetId(): true}
	for _, c := range fr.GetSandboxes() {
		if seen[c.GetId()] || c.GetParentId() != src.GetId() {
			t.Errorf("child %v", c)
		}
		seen[c.GetId()] = true
	}

	// Diff two sandboxes: a child's change and its behaviour show up.
	kid := fr.GetSandboxes()[0].GetId()
	if err := h.be.CopyIn(ctx, kid, "/work/new", strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if err := h.be.CopyIn(ctx, kid, "/work/state", strings.NewReader("v2")); err != nil {
		t.Fatal(err)
	}
	_ = h.svc.eventLogFor(kid).Emit(ctx, events.SourceHost, events.Exec{PID: 5, PPID: 1, Path: "/bin/sh", Argv: []string{"sh", "-c", "make test"}})
	_ = h.svc.eventLogFor(src.GetId()).Emit(ctx, events.SourceHost, events.DNS{QName: "pypi.org", QType: "A", Allowed: true})
	time.Sleep(10 * time.Millisecond)
	d, err := h.client.Diff(ctx, &qtdv1.DiffRequest{SandboxId: kid, AgainstSandboxId: src.GetId()})
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]qtdv1.Change_Kind{}
	for _, c := range d.GetChanges() {
		kinds[c.GetPath()] = c.GetKind()
	}
	if kinds["/work/new"] != qtdv1.Change_KIND_ADDED || kinds["/work/state"] != qtdv1.Change_KIND_MODIFIED || len(kinds) != 2 {
		t.Errorf("file diff: %v", kinds)
	}
	ev := d.GetEvents()
	if strings.Join(ev.GetOnlyInSandbox(), "|") != "exec sh -c make test" || strings.Join(ev.GetOnlyInAgainst(), "|") != "dns pypi.org" {
		t.Errorf("events diff: %v", ev)
	}

	// Errors.
	for name, err := range map[string]error{
		"fork 0":             rpcErr(h.client.Fork(ctx, &qtdv1.ForkRequest{SandboxId: src.GetId(), Count: 0})),
		"fork 65":            rpcErr(h.client.Fork(ctx, &qtdv1.ForkRequest{SandboxId: src.GetId(), Count: 65})),
		"restore a bad id":   rpcErr(h.client.Restore(ctx, &qtdv1.RestoreRequest{SnapshotId: "../../etc"})),
		"restore a missing":  rpcErr(h.client.Restore(ctx, &qtdv1.RestoreRequest{SnapshotId: "sn-000000000000"})),
		"snapshot a missing": rpcErr(h.client.Snapshot(ctx, &qtdv1.SnapshotRequest{SandboxId: "abcdef012345"})),
	} {
		want := map[string]codes.Code{
			"fork 0": codes.InvalidArgument, "fork 65": codes.InvalidArgument, "restore a bad id": codes.InvalidArgument,
			"restore a missing": codes.NotFound, "snapshot a missing": codes.NotFound,
		}[name]
		if status.Code(err) != want {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}

	// Delete: the snapshot goes; sandboxes made from it don't care. rm leaves nothing.
	if _, err := h.client.DeleteSnapshot(ctx, &qtdv1.DeleteSnapshotRequest{SnapshotId: snap.GetSnapshotId()}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.client.DeleteSnapshot(ctx, &qtdv1.DeleteSnapshotRequest{SnapshotId: snap.GetSnapshotId()}); err != nil {
		t.Errorf("delete is not idempotent: %v", err)
	}
	if left, _ := os.ReadDir(filepath.Join(h.data, "snapshots")); len(left) != 0 {
		t.Errorf("snapshots left: %v", left)
	}
	for id := range seen {
		if _, err := h.client.Destroy(ctx, &qtdv1.DestroyRequest{SandboxId: id}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.client.Destroy(ctx, &qtdv1.DestroyRequest{SandboxId: r.GetId()}); err != nil {
		t.Fatal(err)
	}
	if left, _ := os.ReadDir(filepath.Join(h.data, "sandboxes")); len(left) != 0 {
		t.Errorf("sandboxes left: %v", left)
	}
}

func TestSnapshotNeedsTheCapability(t *testing.T) {
	h := newHarness(t, 0, nil) // gvisor-like: no snapshots, no fork
	sb := h.create(t, &qtdv1.CreateRequest{})
	ctx := context.Background()
	if _, err := h.client.Snapshot(ctx, &qtdv1.SnapshotRequest{SandboxId: sb.GetId()}); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--isolation=vm") {
		t.Errorf("snapshot: %v", err)
	}
	if _, err := h.client.Fork(ctx, &qtdv1.ForkRequest{SandboxId: sb.GetId(), Count: 2}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("fork: %v", err)
	}
}

func rpcErr[T any](_ T, err error) error { return err }
