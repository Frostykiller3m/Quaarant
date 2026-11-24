package daemon

import (
	"archive/tar"
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"sort"
	"strings"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

const copyChunk = 1 << 20 // tar bytes per message (proto contract: at most 1 MiB)

func validateSandboxPath(p string) error {
	if p == "" {
		return errors.New("path is required")
	}
	return validateWorkdir(p)
}

// CopyIn implements the CopyIn RPC: header first, then tar chunks, extracted by the backend.
func (s *Service) CopyIn(stream grpc.ClientStreamingServer[qtdv1.CopyInRequest, qtdv1.CopyInResponse]) error {
	ctx := stream.Context()
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "copy in: %v", err)
	}
	h := first.GetHeader()
	if h == nil {
		return status.Error(codes.InvalidArgument, "copy in: the first message must be header")
	}
	if err := validateSandboxPath(h.GetDir()); err != nil {
		return status.Errorf(codes.InvalidArgument, "copy in: %v", err)
	}
	_, be, err := s.backendFor(h.GetSandboxId())
	if err != nil {
		return err
	}

	pr, pw := io.Pipe() // client chunks -> backend
	var total uint64
	go func() {
		for {
			msg, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				_ = pw.Close()
				return
			}
			if err != nil {
				_ = pw.CloseWithError(err)
				return
			}
			chunk := msg.GetTarChunk()
			if msg.GetHeader() != nil || len(chunk) > copyChunk {
				_ = pw.CloseWithError(errors.New("bad copy-in message"))
				return
			}
			total += uint64(len(chunk))
			if _, err := pw.Write(chunk); err != nil {
				return
			}
		}
	}()
	// Count entries from a copy of the stream; the counter always drains, so it never stalls
	// the backend.
	cr, cw := io.Pipe()
	counted := make(chan uint32, 1)
	go func() {
		var n uint32
		tr := tar.NewReader(cr)
		for {
			if _, err := tr.Next(); err != nil {
				break
			}
			n++
		}
		_, _ = io.Copy(io.Discard, cr)
		counted <- n
	}()
	err = be.CopyIn(ctx, h.GetSandboxId(), h.GetDir(), io.TeeReader(pr, cw))
	_ = pr.CloseWithError(io.ErrClosedPipe) // stop the receiver if the backend stopped early
	_ = cw.Close()
	files := <-counted
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "copy in: %v", err)
	}
	s.log.Info("copy in", "id", h.GetSandboxId(), "dir", h.GetDir(), "bytes", total, "entries", files)
	return stream.SendAndClose(&qtdv1.CopyInResponse{Bytes: total, Files: files})
}

// CopyOut implements the CopyOut RPC: the backend's tar, chunked.
func (s *Service) CopyOut(req *qtdv1.CopyOutRequest, stream grpc.ServerStreamingServer[qtdv1.CopyOutResponse]) error {
	if err := validateSandboxPath(req.GetPath()); err != nil {
		return status.Errorf(codes.InvalidArgument, "copy out: %v", err)
	}
	_, be, err := s.backendFor(req.GetSandboxId())
	if err != nil {
		return err
	}
	bw := bufio.NewWriterSize(chunkSender{stream}, copyChunk)
	if err := be.CopyOut(stream.Context(), req.GetSandboxId(), req.GetPath(), bw); err != nil {
		return status.Errorf(codes.FailedPrecondition, "copy out: %v", err)
	}
	if err := bw.Flush(); err != nil {
		return status.Errorf(codes.Unavailable, "copy out: %v", err)
	}
	return nil
}

type chunkSender struct {
	stream grpc.ServerStreamingServer[qtdv1.CopyOutResponse]
}

func (c chunkSender) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		k := min(len(p), copyChunk)
		if err := c.stream.Send(&qtdv1.CopyOutResponse{TarChunk: append([]byte(nil), p[:k]...)}); err != nil {
			return n, err
		}
		n += k
		p = p[k:]
	}
	return n, nil
}

// Diff implements the Diff RPC.
func (s *Service) Diff(ctx context.Context, req *qtdv1.DiffRequest) (*qtdv1.DiffResponse, error) {
	if req.GetAgainstSandboxId() != "" {
		return s.diffSandboxes(ctx, req.GetSandboxId(), req.GetAgainstSandboxId())
	}
	_, be, err := s.backendFor(req.GetSandboxId())
	if err != nil {
		return nil, err
	}
	changes, err := be.Diff(ctx, req.GetSandboxId())
	truncated := errors.Is(err, backend.ErrDiffTruncated)
	if err != nil && !truncated {
		return nil, status.Errorf(codes.FailedPrecondition, "diff: %v", err)
	}
	changes = hideHoneytokens(s.honeySet(req.GetSandboxId()), changes)
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	out := &qtdv1.DiffResponse{Truncated: truncated, Changes: make([]*qtdv1.Change, 0, len(changes))}
	for _, c := range changes {
		pc := &qtdv1.Change{Kind: kindToProto(c.Kind), Mode: posixMode(c.Mode), Size: uint64(max(c.Size, 0)), Sha256: c.SHA256}
		pc.Path, pc.PathRaw = utf8Field(c.Path)
		pc.LinkTarget, pc.LinkTargetRaw = utf8Field(c.LinkTarget)
		out.Changes = append(out.Changes, pc)
	}
	return out, nil
}

// utf8Field returns s for a proto string field, plus its raw bytes when s is not valid UTF-8
// (a proto string must be UTF-8; sandbox file names need not be).
func utf8Field(s string) (string, []byte) {
	if utf8.ValidString(s) {
		return s, nil
	}
	return strings.ToValidUTF8(s, "�"), []byte(s)
}

func kindToProto(k backend.ChangeKind) qtdv1.Change_Kind {
	switch k {
	case backend.Added:
		return qtdv1.Change_KIND_ADDED
	case backend.Modified:
		return qtdv1.Change_KIND_MODIFIED
	case backend.Deleted:
		return qtdv1.Change_KIND_DELETED
	}
	return qtdv1.Change_KIND_UNSPECIFIED
}

// posixMode converts an fs.FileMode to a POSIX st_mode.
func posixMode(m fs.FileMode) uint32 {
	mode := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		mode |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		mode |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		mode |= 0o1000
	}
	switch {
	case m.IsDir():
		mode |= 0o040000
	case m&fs.ModeSymlink != 0:
		mode |= 0o120000
	case m&fs.ModeNamedPipe != 0:
		mode |= 0o010000
	case m&fs.ModeSocket != 0:
		mode |= 0o140000
	case m&fs.ModeCharDevice != 0:
		mode |= 0o020000
	case m&fs.ModeDevice != 0:
		mode |= 0o060000
	default:
		mode |= 0o100000
	}
	return mode
}
