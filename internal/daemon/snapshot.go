package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/honeytoken"
	"github.com/Frostykiller3m/Quaarant/internal/netpol"
)

var snapshotIDRe = regexp.MustCompile(`^sn-[a-f0-9]{12}$`)

// snapRecord is <DataDir>/snapshots/<id>/qt-snapshot.json.
type snapRecord struct {
	ID        string            `json:"id"`
	Name      string            `json:"name,omitempty"`
	Source    record            `json:"source"` // the sandbox's record when it was taken
	Isolation backend.Isolation `json:"isolation"`
	Memory    bool              `json:"memory"`
	Created   time.Time         `json:"created"`
}

func (s *Service) snapshotsDir() string         { return filepath.Join(s.opts.DataDir, "snapshots") }
func (s *Service) snapshotDir(id string) string { return filepath.Join(s.snapshotsDir(), id) }

func (s *Service) loadSnapshot(id string) (*snapRecord, error) {
	if !snapshotIDRe.MatchString(id) {
		return nil, status.Errorf(codes.InvalidArgument, "invalid snapshot id %.64q", id)
	}
	raw, err := os.ReadFile(filepath.Join(s.snapshotDir(id), "qt-snapshot.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, status.Errorf(codes.NotFound, "no snapshot %s", id)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "snapshot %s: %v", id, err)
	}
	var r snapRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, status.Errorf(codes.Internal, "snapshot %s: %v", id, err)
	}
	return &r, nil
}

func (r *snapRecord) ref(dir string) backend.SnapshotRef {
	return backend.SnapshotRef{ID: r.ID, Backend: r.Isolation, Memory: r.Memory, Path: dir}
}

// Snapshot implements the Snapshot RPC.
func (s *Service) Snapshot(ctx context.Context, req *qtdv1.SnapshotRequest) (*qtdv1.SnapshotResponse, error) {
	rec, be, err := s.backendFor(req.GetSandboxId())
	if err != nil {
		return nil, err
	}
	need := backend.CapDiskSnapshot
	if req.GetIncludeMemory() {
		need = backend.CapMemorySnapshot
	}
	if err := backend.Require(be, need); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "snapshot: %v (use --isolation=vm)", err)
	}
	if len(req.GetName()) > 128 || strings.ContainsAny(req.GetName(), "\x00\n") {
		return nil, status.Error(codes.InvalidArgument, "snapshot name: at most 128 characters, one line")
	}
	unlock := s.lock(rec.ID)
	defer unlock()
	id := "sn-" + newID()
	dir := s.snapshotDir(id)
	if err := os.MkdirAll(s.snapshotsDir(), 0o700); err != nil {
		return nil, status.Errorf(codes.Internal, "snapshot: %v", err)
	}
	ref, err := be.Snapshot(ctx, rec.ID, backend.SnapshotOptions{Memory: req.GetIncludeMemory(), Dir: dir})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "snapshot: %v", err)
	}
	sr := snapRecord{ID: id, Name: req.GetName(), Source: *rec, Isolation: rec.Isolation, Memory: ref.Memory, Created: time.Now().UTC()}
	if set := s.honeySet(rec.ID); set != nil {
		if err := set.Save(filepath.Join(dir, "honeytokens.json")); err != nil {
			_ = s.deleteSnapshotFiles(ctx, &sr)
			return nil, status.Errorf(codes.Internal, "snapshot: %v", err)
		}
	}
	if err := writeJSONFile(filepath.Join(dir, "qt-snapshot.json"), sr); err != nil {
		_ = s.deleteSnapshotFiles(ctx, &sr)
		return nil, status.Errorf(codes.Internal, "snapshot: %v", err)
	}
	s.log.Info("snapshot taken", "id", id, "sandbox", rec.ID, "memory", ref.Memory)
	return &qtdv1.SnapshotResponse{SnapshotId: id, IncludesMemory: ref.Memory}, nil
}

// ListSnapshots implements the ListSnapshots RPC.
func (s *Service) ListSnapshots(_ context.Context, _ *qtdv1.ListSnapshotsRequest) (*qtdv1.ListSnapshotsResponse, error) {
	entries, err := os.ReadDir(s.snapshotsDir())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, status.Errorf(codes.Internal, "list snapshots: %v", err)
	}
	out := &qtdv1.ListSnapshotsResponse{}
	for _, e := range entries {
		if !snapshotIDRe.MatchString(e.Name()) {
			continue // .fork-* and anything else
		}
		r, err := s.loadSnapshot(e.Name())
		if err != nil {
			continue
		}
		var size uint64
		_ = filepath.WalkDir(s.snapshotDir(r.ID), func(_ string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if fi, err := d.Info(); err == nil {
					size += uint64(max(allocated(fi), 0))
				}
			}
			return nil
		})
		out.Snapshots = append(out.Snapshots, &qtdv1.SnapshotInfo{
			Id: r.ID, Name: r.Name, SandboxId: r.Source.ID, Isolation: isolationToProto(r.Isolation),
			IncludesMemory: r.Memory, CreatedAt: timestamppb.New(r.Created), Bytes: size, Image: r.Source.Image,
		})
	}
	sort.Slice(out.Snapshots, func(i, j int) bool {
		return out.Snapshots[i].GetCreatedAt().AsTime().Before(out.Snapshots[j].GetCreatedAt().AsTime())
	})
	return out, nil
}

// DeleteSnapshot implements the DeleteSnapshot RPC.
func (s *Service) DeleteSnapshot(ctx context.Context, req *qtdv1.DeleteSnapshotRequest) (*qtdv1.DeleteSnapshotResponse, error) {
	r, err := s.loadSnapshot(req.GetSnapshotId())
	if status.Code(err) == codes.NotFound {
		return &qtdv1.DeleteSnapshotResponse{}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.deleteSnapshotFiles(ctx, r); err != nil {
		return nil, status.Errorf(codes.Internal, "delete snapshot: %v", err)
	}
	s.log.Info("snapshot deleted", "id", r.ID)
	return &qtdv1.DeleteSnapshotResponse{}, nil
}

func (s *Service) deleteSnapshotFiles(ctx context.Context, r *snapRecord) error {
	dir := s.snapshotDir(r.ID)
	if be, ok := s.backends[r.Isolation]; ok {
		if d, ok := be.(backend.SnapshotDeleter); ok {
			return d.DeleteSnapshot(ctx, r.ref(dir))
		}
	}
	return os.RemoveAll(dir)
}

// child prepares a new sandbox that will start from src's state: its own id, workspace,
// network link (src's policy) and src's honeytokens (the restored memory or disk holds them).
func (s *Service) child(ctx context.Context, src *record, be backend.Backend, honey *honeytoken.Set, labels map[string]string) (*record, backend.Spec, error) {
	id := newID()
	rec := *src
	rec.ID, rec.CreatedAt, rec.ParentID, rec.Net = id, time.Now().UTC(), src.ID, nil
	rec.Hostname = "qt-" + id
	rec.Labels = map[string]string{}
	for k, v := range src.Labels {
		rec.Labels[k] = v
	}
	for k, v := range labels {
		rec.Labels[k] = v
	}
	ws := s.reg.workspace(id)
	if err := os.Mkdir(ws, 0o700); err != nil {
		return nil, backend.Spec{}, status.Errorf(codes.Internal, "create workspace: %v", err)
	}
	if err := s.reg.save(&rec); err != nil {
		_ = os.RemoveAll(ws)
		return nil, backend.Spec{}, status.Errorf(codes.Internal, "%v", err)
	}
	var rules netpol.Rules
	if honey != nil {
		if err := honey.Save(s.honeyPath(id)); err != nil {
			s.cleanup(id, be)
			return nil, backend.Spec{}, status.Errorf(codes.Internal, "honeytokens: %v", err)
		}
		s.useHoneytokens(id, honey)
	}
	network := backend.Network{None: true}
	if src.Net != nil {
		if s.opts.Net == nil {
			s.cleanup(id, be)
			return nil, backend.Spec{}, status.Error(codes.FailedPrecondition, "this qtd has no sandbox networking")
		}
		rules = src.Net.rules()
		rules.Honey = honeytoken.NewMatcher(honey)
		l, nr, err := s.attach(ctx, id, rec.Isolation, be, rules)
		if err != nil {
			s.cleanup(id, be)
			return nil, backend.Spec{}, err
		}
		rec.Net = nr
		if err := s.reg.save(&rec); err != nil {
			s.cleanup(id, be)
			return nil, backend.Spec{}, status.Errorf(codes.Internal, "%v", err)
		}
		network = l.Network()
	}
	// The image (by digest: served from the cache) for the spec's root filesystem; a restored
	// VM boots its snapshot's disk, but the spec is the same shape as a new sandbox's.
	img, err := s.opts.Images.Pull(ctx, rec.Image)
	if err != nil {
		s.cleanup(id, be)
		return nil, backend.Spec{}, status.Errorf(codes.Internal, "image: %v", err)
	}
	rootfs := img.RootFS
	if rec.Isolation == backend.IsolationVM {
		eb, ok := s.opts.Images.(ext4Builder)
		if !ok {
			s.cleanup(id, be)
			return nil, backend.Spec{}, status.Error(codes.FailedPrecondition, "this image store cannot build disk images for vm isolation")
		}
		if rootfs, err = eb.Ext4(ctx, img); err != nil {
			s.cleanup(id, be)
			return nil, backend.Spec{}, status.Errorf(codes.Internal, "vm disk image: %v", err)
		}
	}
	spec := backend.Spec{
		ID: id, Image: rec.Image, RootFS: rootfs, Workspace: ws, Hostname: rec.Hostname, User: rec.User, Env: rec.Env,
		Workdir: rec.Workdir, Limits: rec.Limits, Network: network, Events: s.eventLogFor(id), Labels: rec.Labels,
	}
	return &rec, spec, nil
}

// Restore implements the Restore RPC.
func (s *Service) Restore(ctx context.Context, req *qtdv1.RestoreRequest) (*qtdv1.RestoreResponse, error) {
	sr, err := s.loadSnapshot(req.GetSnapshotId())
	if err != nil {
		return nil, err
	}
	if err := validateLabels(req.GetLabels()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	be, ok := s.backends[sr.Isolation]
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "isolation %q is not available on this host", sr.Isolation)
	}
	var honey *honeytoken.Set
	if h, err := honeytoken.Load(filepath.Join(s.snapshotDir(sr.ID), "honeytokens.json")); err == nil {
		honey = h
	}
	rec, spec, err := s.child(ctx, &sr.Source, be, honey, req.GetLabels())
	if err != nil {
		return nil, err
	}
	unlock := s.lock(rec.ID)
	defer unlock()
	if err := be.Restore(ctx, sr.ref(s.snapshotDir(sr.ID)), spec); err != nil {
		s.cleanup(rec.ID, be)
		return nil, status.Errorf(codes.Internal, "restore: %v", err)
	}
	s.log.Info("sandbox restored", "id", rec.ID, "snapshot", sr.ID)
	return &qtdv1.RestoreResponse{Sandbox: s.toProto(ctx, rec)}, nil
}

// Fork implements the Fork RPC.
func (s *Service) Fork(ctx context.Context, req *qtdv1.ForkRequest) (*qtdv1.ForkResponse, error) {
	src, be, err := s.backendFor(req.GetSandboxId())
	if err != nil {
		return nil, err
	}
	if err := backend.Require(be, backend.CapFork); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "fork: %v (use --isolation=vm)", err)
	}
	n := int(req.GetCount())
	if n < 1 || n > 64 {
		return nil, status.Error(codes.InvalidArgument, "fork: count must be 1-64")
	}
	if err := validateLabels(req.GetLabels()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	unlock := s.lock(src.ID)
	defer unlock()
	var recs []*record
	var specs []backend.Spec
	fail := func(err error) (*qtdv1.ForkResponse, error) {
		for _, r := range recs {
			s.cleanup(r.ID, be)
		}
		return nil, err
	}
	for range n {
		rec, spec, err := s.child(ctx, src, be, s.honeySet(src.ID), req.GetLabels())
		if err != nil {
			return fail(err)
		}
		recs, specs = append(recs, rec), append(specs, spec)
	}
	if err := be.Fork(ctx, src.ID, specs); err != nil {
		return fail(status.Errorf(codes.Internal, "fork: %v", err))
	}
	out := &qtdv1.ForkResponse{}
	for _, r := range recs {
		out.Sandboxes = append(out.Sandboxes, s.toProto(ctx, r))
	}
	s.log.Info("sandbox forked", "id", src.ID, "children", n)
	return out, nil
}

// diffSandboxes compares two running sandboxes: their whole filesystems (as their backends
// list them) and their behaviour (normalized facts from their event logs).
func (s *Service) diffSandboxes(ctx context.Context, a, b string) (*qtdv1.DiffResponse, error) {
	ra, bea, err := s.backendFor(a)
	if err != nil {
		return nil, err
	}
	rb, beb, err := s.backendFor(b)
	if err != nil {
		return nil, err
	}
	ma, oka := bea.(backend.Manifester)
	mb, okb := beb.(backend.Manifester)
	if !oka || !okb {
		return nil, status.Error(codes.FailedPrecondition, "comparing two sandboxes needs isolation that can list a running filesystem (vm)")
	}
	ea, err := ma.Manifest(ctx, ra.ID)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "diff: %s: %v", a, err)
	}
	eb, err := mb.Manifest(ctx, rb.ID)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "diff: %s: %v", b, err)
	}
	resp := &qtdv1.DiffResponse{}
	for _, c := range compareManifests(ea, eb) {
		if len(resp.Changes) >= maxDiffChanges {
			resp.Truncated = true
			break
		}
		resp.Changes = append(resp.Changes, c)
	}
	fa, fb := s.facts(a), s.facts(b)
	ed := &qtdv1.EventsDiff{}
	for _, pair := range []struct {
		from, other map[string]bool
		out         *[]string
	}{{fa, fb, &ed.OnlyInSandbox}, {fb, fa, &ed.OnlyInAgainst}} {
		for f := range pair.from {
			if !pair.other[f] {
				*pair.out = append(*pair.out, f)
			}
		}
		sort.Strings(*pair.out)
		if len(*pair.out) > maxEventFacts {
			*pair.out, ed.Truncated = (*pair.out)[:maxEventFacts], true
		}
	}
	resp.Events = ed
	return resp, nil
}

const (
	maxDiffChanges = 20000
	maxEventFacts  = 500
)

// compareManifests reports a relative to b: added (only in a), deleted (only in b), modified.
func compareManifests(a, b []backend.Entry) []*qtdv1.Change {
	idx := make(map[string]backend.Entry, len(b))
	for _, e := range b {
		idx[e.Path] = e
	}
	seen := make(map[string]bool, len(a))
	var out []*qtdv1.Change
	add := func(e backend.Entry, k qtdv1.Change_Kind) {
		c := &qtdv1.Change{Kind: k, Mode: entryMode(e), Size: uint64(max(e.Size, 0)), Sha256: e.SHA256}
		c.Path, c.PathRaw = utf8Field(e.Path)
		c.LinkTarget, c.LinkTargetRaw = utf8Field(e.Link)
		if k == qtdv1.Change_KIND_DELETED {
			c.Sha256, c.Size = "", 0
		}
		out = append(out, c)
	}
	for _, e := range a {
		seen[e.Path] = true
		o, ok := idx[e.Path]
		switch {
		case !ok:
			add(e, qtdv1.Change_KIND_ADDED)
		case o.Type != e.Type || o.Mode != e.Mode || o.Link != e.Link || o.Size != e.Size || o.SHA256 != e.SHA256:
			add(e, qtdv1.Change_KIND_MODIFIED)
		}
	}
	for _, e := range b {
		if !seen[e.Path] {
			add(e, qtdv1.Change_KIND_DELETED)
		}
	}
	slices.SortFunc(out, func(x, y *qtdv1.Change) int { return strings.Compare(x.GetPath(), y.GetPath()) })
	return out
}

func entryMode(e backend.Entry) uint32 {
	t := map[string]uint32{"f": 0o100000, "d": 0o040000, "l": 0o120000}[e.Type]
	return t | e.Mode&0o7777
}

// facts are a sandbox's behaviour as comparable strings.
func (s *Service) facts(id string) map[string]bool {
	out := map[string]bool{}
	f, err := os.Open(s.eventsPath(id))
	if err != nil {
		return out
	}
	defer func() { _ = f.Close() }()
	_ = events.ValidateStream(f, func(ev events.Event) error {
		if len(out) > 100000 {
			return nil
		}
		if fact := factOf(ev); fact != "" {
			out[fact] = true
		}
		return nil
	})
	return out
}

func factOf(ev events.Event) string {
	cut := func(s string) string {
		if len(s) > 200 {
			return s[:200] + "…"
		}
		return s
	}
	switch ev.Kind {
	case events.KindExec:
		var x events.Exec
		if json.Unmarshal(ev.Data, &x) == nil && len(x.Argv) > 0 {
			return cut("exec " + strings.Join(x.Argv, " "))
		}
	case events.KindFile:
		var x events.File
		if json.Unmarshal(ev.Data, &x) == nil && x.Op != "open" && x.Errno == "" {
			if x.NewPath != "" {
				return cut(x.Op + " " + x.Path + " -> " + x.NewPath)
			}
			return cut(x.Op + " " + x.Path)
		}
	case events.KindNet:
		var x events.Net
		if json.Unmarshal(ev.Data, &x) == nil && x.Op == "connect" {
			host := x.DstIP
			if x.SNI != "" {
				host = x.SNI
			} else if x.HTTPHost != "" {
				host = x.HTTPHost
			}
			v := "connect"
			if x.Allowed != nil && !*x.Allowed {
				v = "refused"
			}
			return cut(fmt.Sprintf("%s %s:%d", v, host, x.DstPort))
		}
	case events.KindDNS:
		var x events.DNS
		if json.Unmarshal(ev.Data, &x) == nil {
			return cut("dns " + x.QName)
		}
	case events.KindHoneytoken:
		var x events.Honeytoken
		if json.Unmarshal(ev.Data, &x) == nil {
			return cut("honeytoken " + x.Trigger + " " + x.TokenKind)
		}
	case events.KindPolicyDenied:
		var x events.PolicyDenied
		if json.Unmarshal(ev.Data, &x) == nil {
			return cut("denied " + x.Reason + " " + x.Target)
		}
	}
	return ""
}

func writeJSONFile(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}
