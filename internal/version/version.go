// Package version exposes build metadata for all quarantine binaries.
//
// Version, Commit and Date are set at link time:
//
//	go build -ldflags "-X github.com/Frostykiller3m/Quaarant/internal/version.Version=v0.1.0 ..."
//
// When they are not set, Get falls back to the VCS info embedded by the Go toolchain.
package version

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Set via -ldflags -X. Keep these as plain string vars.
var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// Info is the build metadata of the running binary.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	Dirty     bool   `json:"dirty,omitempty"`
	GoVersion string `json:"go"`
	Platform  string `json:"platform"`
}

// readBuildInfo is replaceable in tests.
var readBuildInfo = debug.ReadBuildInfo

// Get returns the build metadata, preferring ldflags values over embedded VCS info.
func Get() Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		Date:      Date,
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
	}
	if bi, ok := readBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.Date == "" {
					info.Date = s.Value
				}
			case "vcs.modified":
				info.Dirty = s.Value == "true"
			}
		}
		if info.Version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	if info.Date == "" {
		info.Date = "unknown"
	}
	return info
}

// ShortCommit returns at most the first 12 characters of the commit hash.
func (i Info) ShortCommit() string {
	if len(i.Commit) > 12 {
		return i.Commit[:12]
	}
	return i.Commit
}

// String renders a one-line summary, e.g.
// "qtd v0.1.0 (0123456789ab, 2026-11-23T10:00:00Z, go1.23.4 linux/amd64)".
func (i Info) String(binary string) string {
	commit := i.ShortCommit()
	if i.Dirty {
		commit += "-dirty"
	}
	return fmt.Sprintf("%s %s (%s, %s, %s %s)", binary, i.Version, commit, i.Date, i.GoVersion, i.Platform)
}

// Text renders a multi-line, human-readable block.
func (i Info) Text(binary string) string {
	var b strings.Builder
	commit := i.Commit
	if i.Dirty {
		commit += " (dirty)"
	}
	fmt.Fprintf(&b, "%s %s\n", binary, i.Version)
	fmt.Fprintf(&b, "  commit:   %s\n", commit)
	fmt.Fprintf(&b, "  built:    %s\n", i.Date)
	fmt.Fprintf(&b, "  go:       %s\n", i.GoVersion)
	fmt.Fprintf(&b, "  platform: %s\n", i.Platform)
	return b.String()
}

// JSON renders the info as indented JSON.
func (i Info) JSON() ([]byte, error) {
	out, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal version info: %w", err)
	}
	return out, nil
}
