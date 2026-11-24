// Package vet runs a git repository's code in a sandbox and judges it: `qt run <git-url>`.
//
// The repository is cloned inside a throwaway sandbox (network: its git host only) and moves
// to the run sandbox as a tar stream; nothing from it is executed or unpacked on the host.
// From its key files a plan is made (Claude, or rules from the manifests without an API
// key): a base image, setup and run commands, a network policy. Risky commands are flagged by
// rules that don't depend on the plan's author, the user approves, the plan runs in a fresh
// sandbox with honeytokens planted, and the report prints at the end.
package vet

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/Frostykiller3m/Quaarant/internal/netpol"
)

// Repo is a validated git URL.
type Repo struct {
	URL  string // https://host/path
	Host string
	Name string // last path element, without .git
}

var repoPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~-]+(/[A-Za-z0-9._~-]+){0,7}/?$`)

// IsGitURL reports whether s should be treated as a repository rather than an image.
func IsGitURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "git@")
}

// ParseRepo accepts https://host/owner/repo[.git] and git@host:owner/repo[.git] (cloned over
// https: the sandbox has no SSH keys, only fake ones).
func ParseRepo(s string) (Repo, error) {
	if strings.HasPrefix(s, "git@") {
		host, p, ok := strings.Cut(strings.TrimPrefix(s, "git@"), ":")
		if !ok {
			return Repo{}, fmt.Errorf("git URL %.200q: want git@host:owner/repo", s)
		}
		s = "https://" + host + "/" + p
	}
	if strings.HasPrefix(s, "http://") {
		return Repo{}, errors.New("plain http git URLs are not allowed: use https")
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return Repo{}, fmt.Errorf("git URL %.200q: want https://host/owner/repo", s)
	}
	host, err := netpol.ParseDomain(u.Hostname())
	if err != nil {
		return Repo{}, fmt.Errorf("git URL host: %w", err)
	}
	if !repoPathRe.MatchString(u.Path) || strings.Contains(u.Path, "/.") {
		return Repo{}, fmt.Errorf("git URL path %.200q: letters, digits and ._~- only", u.Path)
	}
	p := strings.TrimSuffix(u.Path, "/")
	name := strings.TrimSuffix(p[strings.LastIndex(p, "/")+1:], ".git")
	if name == "" {
		return Repo{}, errors.New("git URL has no repository name")
	}
	return Repo{URL: "https://" + host + p, Host: host, Name: name}, nil
}
