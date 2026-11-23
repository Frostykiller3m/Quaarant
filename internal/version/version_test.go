package version

import (
	"encoding/json"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func withBuild(t *testing.T, v, c, d string, bi *debug.BuildInfo) {
	t.Helper()
	oldV, oldC, oldD, oldR := Version, Commit, Date, readBuildInfo
	t.Cleanup(func() { Version, Commit, Date, readBuildInfo = oldV, oldC, oldD, oldR })
	Version, Commit, Date = v, c, d
	readBuildInfo = func() (*debug.BuildInfo, bool) { return bi, bi != nil }
}

func TestGet(t *testing.T) {
	vcs := &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123"},
			{Key: "vcs.time", Value: "2026-11-23T10:00:00Z"},
			{Key: "vcs.modified", Value: "true"},
		},
	}
	tests := []struct {
		name                string
		v, c, d             string
		bi                  *debug.BuildInfo
		wantV, wantC, wantD string
		wantDirty           bool
	}{
		{"ldflags take precedence", "v1.2.3", "deadbeef", "2026-01-01", vcs, "v1.2.3", "deadbeef", "2026-01-01", true},
		{"vcs fallback", "dev", "", "", vcs, "dev", "0123456789abcdef0123", "2026-11-23T10:00:00Z", true},
		{"no build info", "dev", "", "", nil, "dev", "unknown", "unknown", false},
		{"module version", "dev", "", "", &debug.BuildInfo{Main: debug.Module{Version: "v0.4.0"}}, "v0.4.0", "unknown", "unknown", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withBuild(t, tt.v, tt.c, tt.d, tt.bi)
			got := Get()
			if got.Version != tt.wantV || got.Commit != tt.wantC || got.Date != tt.wantD || got.Dirty != tt.wantDirty {
				t.Fatalf("Get() = %+v, want version=%q commit=%q date=%q dirty=%v",
					got, tt.wantV, tt.wantC, tt.wantD, tt.wantDirty)
			}
			if got.GoVersion != runtime.Version() || got.Platform != runtime.GOOS+"/"+runtime.GOARCH {
				t.Fatalf("runtime fields wrong: %+v", got)
			}
		})
	}
}

func TestRender(t *testing.T) {
	i := Info{
		Version: "v1.0.0", Commit: "0123456789abcdef", Date: "2026-11-23", Dirty: true,
		GoVersion: "go1.23.4", Platform: "linux/amd64",
	}

	if got, want := i.String("qtd"), "qtd v1.0.0 (0123456789ab-dirty, 2026-11-23, go1.23.4 linux/amd64)"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	text := i.Text("qt")
	for _, want := range []string{
		"qt v1.0.0\n",
		"commit:   0123456789abcdef (dirty)",
		"built:    2026-11-23",
		"platform: linux/amd64",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("Text() missing %q:\n%s", want, text)
		}
	}

	raw, err := i.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var back Info
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("JSON() is not valid JSON: %v", err)
	}
	if back != i {
		t.Errorf("JSON round trip = %+v, want %+v", back, i)
	}
}

func TestShortCommit(t *testing.T) {
	for in, want := range map[string]string{"": "", "abc": "abc", "0123456789abcdef": "0123456789ab"} {
		if got := (Info{Commit: in}).ShortCommit(); got != want {
			t.Errorf("ShortCommit(%q) = %q, want %q", in, got, want)
		}
	}
}
