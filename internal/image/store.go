// Package image pulls OCI images and keeps their unpacked root filesystems in the data dir,
// cached by manifest digest:
//
//	<dir>/sha256-<hex>/rootfs/       unpacked, read-only lower layer for sandboxes
//	<dir>/sha256-<hex>/config.json   the image config (env, user, workdir, entrypoint)
//	<dir>/sha256-<hex>/image.json    what was pulled, from where, and when
//
// A digest directory appears only by an atomic rename after a complete unpack, so its existence
// means it is complete. Image contents are untrusted: see safetar.Unpack.
package image

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/Frostykiller3m/Quaarant/internal/safetar"
)

// Image is an unpacked image ready to back sandboxes.
type Image struct {
	Ref    string // resolved reference, repo@sha256:...
	Digest string // manifest digest, "sha256:..."
	RootFS string // host path of the unpacked rootfs
	Config v1.Config
}

// FetchFunc resolves a reference to an image (tests use in-memory images).
type FetchFunc func(ctx context.Context, ref name.Reference, platform v1.Platform) (v1.Image, error)

// Store pulls and caches images under Dir.
type Store struct {
	Dir      string
	Limits   safetar.UnpackLimits
	Platform v1.Platform
	Fetch    FetchFunc
	// Chown keeps image file ownership (true when running as root).
	Chown bool
	// TagTTL is how long a tag's resolution to a digest is reused without asking the
	// registry (0 = always ask). Digest references to a cached image never need the network.
	TagTTL time.Duration

	mu    sync.Mutex
	locks map[string]*sync.Mutex
	tags  map[string]tagEntry
}

type tagEntry struct {
	digest v1.Hash
	at     time.Time
}

// NewStore returns a Store that pulls from registries for linux/GOARCH.
func NewStore(dir string) *Store {
	return &Store{
		Dir:      dir,
		Limits:   safetar.DefaultUnpackLimits,
		Platform: v1.Platform{OS: "linux", Architecture: runtime.GOARCH},
		Fetch:    remoteFetch,
		Chown:    os.Geteuid() == 0,
		TagTTL:   10 * time.Minute,
	}
}

func remoteFetch(ctx context.Context, ref name.Reference, p v1.Platform) (v1.Image, error) {
	return remote.Image(ref,
		remote.WithContext(ctx),
		remote.WithPlatform(p),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
}

type meta struct {
	Requested string    `json:"requested"`
	Ref       string    `json:"ref"`
	Digest    string    `json:"digest"`
	PulledAt  time.Time `json:"pulled_at"`
	Stats     safetar.UnpackStats
}

// Pull resolves ref (e.g. "alpine", "python:3.13-slim", "repo@sha256:...") and returns the
// unpacked image, downloading and unpacking it only if that digest is not cached yet.
func (s *Store) Pull(ctx context.Context, ref string) (Image, error) {
	if len(ref) > 512 || strings.TrimSpace(ref) == "" {
		return Image{}, fmt.Errorf("invalid image reference %.64q", ref)
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return Image{}, fmt.Errorf("parse image reference %q: %w", ref, err)
	}
	// Already have it? A digest names exact content; a tag resolved recently is reused.
	if d, ok := s.knownDigest(r); ok {
		if dir := s.digestDir(d); dirExists(dir) {
			return s.load(dir, r.Context().Digest(d.String()).String(), d.String())
		}
	}
	img, err := s.Fetch(ctx, r, s.Platform)
	if err != nil {
		return Image{}, fmt.Errorf("fetch %s: %w", r, err)
	}
	digest, err := img.Digest()
	if err != nil {
		return Image{}, fmt.Errorf("digest of %s: %w", r, err)
	}
	resolved := r.Context().Digest(digest.String()).String()
	s.rememberTag(r, digest)

	lock := s.lockFor(digest.String())
	lock.Lock()
	defer lock.Unlock()

	dir := s.digestDir(digest)
	if _, err := os.Stat(dir); err == nil {
		return s.load(dir, resolved, digest.String())
	}
	if err := s.unpack(ctx, img, dir, ref, resolved, digest.String()); err != nil {
		return Image{}, err
	}
	return s.load(dir, resolved, digest.String())
}

func (s *Store) digestDir(d v1.Hash) string {
	return filepath.Join(s.Dir, d.Algorithm+"-"+d.Hex)
}

func (s *Store) lockFor(key string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locks == nil {
		s.locks = map[string]*sync.Mutex{}
	}
	l, ok := s.locks[key]
	if !ok {
		l = &sync.Mutex{}
		s.locks[key] = l
	}
	return l
}

func (s *Store) unpack(ctx context.Context, img v1.Image, dir, requested, resolved, digest string) (err error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("create image dir: %w", err)
	}
	tmp, err := os.MkdirTemp(s.Dir, ".pull-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(tmp)
		}
	}()
	rawCfg, err := img.RawConfigFile()
	if err != nil {
		return fmt.Errorf("read image config: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "config.json"), rawCfg, 0o600); err != nil {
		return fmt.Errorf("write image config: %w", err)
	}
	rootfs := filepath.Join(tmp, "rootfs")
	if err := os.Mkdir(rootfs, 0o755); err != nil { //nolint:gosec // G301: image root; sandbox users must traverse it
		return fmt.Errorf("create rootfs: %w", err)
	}
	rc := mutate.Extract(img) // flattened, whiteouts applied; layer digests are verified on read
	defer func() { _ = rc.Close() }()
	stats, err := safetar.Unpack(contextReader{ctx, rc}, rootfs, s.Limits, s.Chown)
	if err != nil {
		return fmt.Errorf("unpack %s: %w", resolved, err)
	}
	m, _ := json.MarshalIndent(meta{requested, resolved, digest, time.Now().UTC(), stats}, "", "  ")
	if err := os.WriteFile(filepath.Join(tmp, "image.json"), m, 0o600); err != nil {
		return fmt.Errorf("write image meta: %w", err)
	}
	if err := os.Rename(tmp, dir); err != nil {
		return fmt.Errorf("commit image: %w", err)
	}
	return nil
}

func (s *Store) load(dir, resolved, digest string) (Image, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "config.json")) //nolint:gosec // G304: dir is our digest directory
	if err != nil {
		return Image{}, fmt.Errorf("read cached image config: %w", err)
	}
	var cf v1.ConfigFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		return Image{}, fmt.Errorf("parse image config: %w", err)
	}
	return Image{Ref: resolved, Digest: digest, RootFS: filepath.Join(dir, "rootfs"), Config: cf.Config}, nil
}

// contextReader stops a long unpack when the request is cancelled.
type contextReader struct {
	ctx context.Context
	r   interface{ Read([]byte) (int, error) }
}

func (c contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// ErrNoUser is returned by LookupUser when the name is not in the image's /etc/passwd.
var ErrNoUser = errors.New("user not found in image")

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// knownDigest is the digest r stands for without asking the registry: its own digest, or a
// tag resolved less than TagTTL ago.
func (s *Store) knownDigest(r name.Reference) (v1.Hash, bool) {
	if d, ok := r.(name.Digest); ok {
		h, err := v1.NewHash(d.DigestStr())
		return h, err == nil
	}
	if s.TagTTL <= 0 {
		return v1.Hash{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.tags[r.Name()]
	if !ok || time.Since(e.at) > s.TagTTL {
		return v1.Hash{}, false
	}
	return e.digest, true
}

func (s *Store) rememberTag(r name.Reference, d v1.Hash) {
	if _, ok := r.(name.Tag); !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tags == nil {
		s.tags = map[string]tagEntry{}
	}
	if len(s.tags) > 4096 {
		clear(s.tags)
	}
	s.tags[r.Name()] = tagEntry{digest: d, at: time.Now()}
}
