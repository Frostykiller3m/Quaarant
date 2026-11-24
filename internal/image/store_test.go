package image

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func testImage(t *testing.T) v1.Image {
	t.Helper()
	base := layerOf(t,
		entry{name: "etc/", typ: tar.TypeDir},
		entry{name: "etc/passwd", typ: tar.TypeReg, body: "root:x:0:0:root:/root:/bin/sh\napp:x:1001:1002:app:/home/app:/bin/sh\n"},
		entry{name: "etc/group", typ: tar.TypeReg, body: "root:x:0:\nstaff:x:50:\n"},
		entry{name: "gone", typ: tar.TypeReg, body: "deleted by the next layer"},
	)
	top := layerOf(t,
		entry{name: ".wh.gone", typ: tar.TypeReg},
		entry{name: "hello", typ: tar.TypeReg, body: "hi\n"},
	)
	img, err := mutate.AppendLayers(empty.Image, base, top)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := img.ConfigFile()
	if err != nil {
		t.Fatal(err)
	}
	cf = cf.DeepCopy()
	cf.Config = v1.Config{Env: []string{"PATH=/bin"}, User: "app", WorkingDir: "/srv", Cmd: []string{"sh"}}
	img, err = mutate.ConfigFile(img, cf)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func layerOf(t *testing.T, entries ...entry) v1.Layer {
	t.Helper()
	data := tarOf(t, entries...).Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func testStore(t *testing.T, img v1.Image, fetches *atomic.Int32) *Store {
	t.Helper()
	s := NewStore(filepath.Join(t.TempDir(), "images"))
	s.Chown = false
	s.Fetch = func(_ context.Context, _ name.Reference, _ v1.Platform) (v1.Image, error) {
		fetches.Add(1)
		return img, nil
	}
	return s
}

func TestPullUnpacksAndCaches(t *testing.T) {
	img := testImage(t)
	var fetches atomic.Int32
	s := testStore(t, img, &fetches)
	ctx := context.Background()

	got, err := s.Pull(ctx, "example.com/test/app:1")
	if err != nil {
		t.Fatal(err)
	}
	d, _ := img.Digest()
	if got.Digest != d.String() || !strings.HasSuffix(got.Ref, "example.com/test/app@"+d.String()) {
		t.Errorf("ref/digest = %s / %s", got.Ref, got.Digest)
	}
	if b, err := os.ReadFile(filepath.Join(got.RootFS, "hello")); err != nil || string(b) != "hi\n" {
		t.Errorf("hello = %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(got.RootFS, "gone")); !os.IsNotExist(err) {
		t.Errorf("whiteout not applied: gone stat err = %v", err)
	}
	if got.Config.User != "app" || got.Config.WorkingDir != "/srv" {
		t.Errorf("config = %+v", got.Config)
	}

	// Mark the cached rootfs; a second pull must reuse it rather than unpack again.
	marker := filepath.Join(got.RootFS, "marker")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	again, err := s.Pull(ctx, "example.com/test/app:1")
	if err != nil {
		t.Fatal(err)
	}
	if again.RootFS != got.RootFS {
		t.Errorf("second pull rootfs %s != %s", again.RootFS, got.RootFS)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Error("second pull unpacked again instead of using the cache")
	}
}

func TestPullConcurrentSameDigest(t *testing.T) {
	var fetches atomic.Int32
	s := testStore(t, testImage(t), &fetches)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			if _, err := s.Pull(context.Background(), "example.com/x:latest"); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	des, err := os.ReadDir(s.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(des) != 1 || !strings.HasPrefix(des[0].Name(), "sha256-") {
		var names []string
		for _, de := range des {
			names = append(names, de.Name())
		}
		t.Errorf("image dir = %v, want exactly one sha256-* entry and no temp dirs", names)
	}
}

func TestPullRejectsBadRefs(t *testing.T) {
	var fetches atomic.Int32
	s := testStore(t, testImage(t), &fetches)
	for _, ref := range []string{"", "  ", "UPPER/case", strings.Repeat("a", 600)} {
		if _, err := s.Pull(context.Background(), ref); err == nil {
			t.Errorf("Pull(%.20q) succeeded", ref)
		}
	}
	if fetches.Load() != 0 {
		t.Errorf("fetched %d times for invalid refs", fetches.Load())
	}
}

func TestLookupUser(t *testing.T) {
	var fetches atomic.Int32
	s := testStore(t, testImage(t), &fetches)
	img, err := s.Pull(context.Background(), "example.com/x:1")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		spec    string
		want    User
		wantErr bool
	}{
		{"", User{0, 0, "/root"}, false},
		{"app", User{1001, 1002, "/home/app"}, false},
		{"1001", User{1001, 1002, "/home/app"}, false},
		{"4242", User{4242, 0, ""}, false},
		{"app:staff", User{1001, 50, "/home/app"}, false},
		{"4242:77", User{4242, 77, ""}, false},
		{"nobody-here", User{}, true},
		{"app:nogroup", User{}, true},
	}
	for _, tt := range tests {
		got, err := LookupUser(img.RootFS, tt.spec)
		if (err != nil) != tt.wantErr || (!tt.wantErr && got != tt.want) {
			t.Errorf("LookupUser(%q) = %+v, %v; want %+v (err %v)", tt.spec, got, err, tt.want, tt.wantErr)
		}
	}
}

type entry struct {
	name     string
	typ      byte
	body     string
	link     string
	mode     int64
	uid, gid int
}

func tarOf(t *testing.T, entries ...entry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			mode = 0o644
			if e.typ == tar.TypeDir {
				mode = 0o755
			}
		}
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: mode, Uid: e.uid, Gid: e.gid}
		if e.typ == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func TestPullSkipsTheRegistryWhenItCan(t *testing.T) {
	img := testImage(t)
	var fetches atomic.Int32
	s := testStore(t, img, &fetches)
	ctx := context.Background()
	got, err := s.Pull(ctx, "example.com/app:1")
	if err != nil || fetches.Load() != 1 {
		t.Fatalf("first pull: %v, %d fetches", err, fetches.Load())
	}
	// Same tag within TagTTL, and the digest itself: no registry round trip.
	for _, ref := range []string{"example.com/app:1", got.Ref} {
		if again, err := s.Pull(ctx, ref); err != nil || again.RootFS != got.RootFS {
			t.Fatalf("pull %s: %+v %v", ref, again, err)
		}
	}
	if fetches.Load() != 1 {
		t.Errorf("fetched %d times, want 1", fetches.Load())
	}
	// With TagTTL 0 every tag pull asks the registry (a digest still doesn't).
	s.TagTTL = 0
	if _, err := s.Pull(ctx, "example.com/app:1"); err != nil || fetches.Load() != 2 {
		t.Errorf("tag with TTL 0: %v, %d fetches", err, fetches.Load())
	}
	if _, err := s.Pull(ctx, got.Ref); err != nil || fetches.Load() != 2 {
		t.Errorf("digest: %v, %d fetches", err, fetches.Load())
	}
	// An unknown digest is fetched.
	other := "example.com/app@sha256:" + strings.Repeat("1", 64)
	_, _ = s.Pull(ctx, other)
	if fetches.Load() != 3 {
		t.Errorf("unknown digest: %d fetches, want 3", fetches.Load())
	}
}
