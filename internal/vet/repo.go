package vet

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
)

// Summary is what the planner sees of a repository: its file list and its key files (both
// bounded). It comes from the tar the clone sandbox produced; the host only reads headers and
// bounded file contents from it.
type Summary struct {
	Files     []string          // relative paths, up to maxListed
	Total     int               // files in the repository
	Bytes     int64             // total size of regular files
	Key       map[string]string // relative path -> content (truncated to maxKeyFile)
	Truncated map[string]bool
}

const (
	maxListed  = 400
	maxKeyFile = 24 << 10
	maxKeyAll  = 160 << 10
)

// keyFileRe are the files that tell how to build and run a project.
var keyFileRe = regexp.MustCompile(`(?i)^(readme(\.[a-z]+)?|package\.json|requirements[^/]*\.txt|pyproject\.toml|setup\.py|setup\.cfg|pipfile|tox\.ini|go\.mod|cargo\.toml|gemfile|[^/]+\.gemspec|composer\.json|makefile|dockerfile|install\.sh|setup\.sh|build\.sh|\.github/workflows/[^/]+\.ya?ml)$`)

// Summarize reads a tar of the repository whose entries start with top/ (CopyOut of the
// clone's directory), skipping .git/.
func Summarize(r io.Reader, top string) (*Summary, error) {
	s := &Summary{Key: map[string]string{}, Truncated: map[string]bool{}}
	tr := tar.NewReader(r)
	keyBytes := 0
	workflows := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read repository archive: %w", err)
		}
		name := strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		rel, ok := strings.CutPrefix(name, top+"/")
		if !ok || rel == ".git" || strings.HasPrefix(rel, ".git/") || h.Typeflag != tar.TypeReg {
			continue
		}
		s.Total++
		s.Bytes += h.Size
		if len(s.Files) < maxListed {
			s.Files = append(s.Files, rel)
		}
		if !keyFileRe.MatchString(rel) || keyBytes >= maxKeyAll {
			continue
		}
		if strings.HasPrefix(rel, ".github/") {
			if workflows++; workflows > 3 {
				continue
			}
		}
		n := min(int64(maxKeyFile), int64(maxKeyAll-keyBytes))
		b, err := io.ReadAll(io.LimitReader(tr, n))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", rel, err)
		}
		s.Key[rel] = string(b)
		s.Truncated[rel] = h.Size > int64(len(b))
		keyBytes += len(b)
	}
	sort.Strings(s.Files)
	return s, nil
}

// has reports whether the repository has a top-level file named like one of names
// (case-insensitive).
func (s *Summary) has(names ...string) (string, bool) {
	for _, f := range s.Files {
		for _, n := range names {
			if strings.EqualFold(f, n) {
				return f, true
			}
		}
	}
	return "", false
}
