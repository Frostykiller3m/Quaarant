// Package honeytoken plants fake credentials in a sandbox and recognizes them afterwards.
//
// Each sandbox gets its own set: an SSH private key, AWS credentials, a .env file of API keys
// and a browser cookie database, all with fresh random values, under the sandbox user's
// $HOME. Nothing legitimate reads them, so opening one is an event; a value showing up in
// DNS, TLS SNI or plaintext egress (raw, hex, base64 or base32) is a red flag.
package honeytoken

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// Token kinds (the event schema's token_kind).
const (
	KindSSHKey   = "ssh_key"
	KindAWS      = "aws_credentials"
	KindEnv      = "env_api_key"
	KindCookies  = "browser_cookies"
	minSecretLen = 16 // shorter values would match by accident
)

// Token is one planted file.
type Token struct {
	ID      string   `json:"id"`   // ht_...: the event's token_id
	Kind    string   `json:"kind"` // token_kind
	Path    string   `json:"path"` // absolute, inside the sandbox
	Content []byte   `json:"content"`
	SHA256  string   `json:"sha256"`
	Secrets []string `json:"secrets"` // the values that must never leave
}

// Set is a sandbox's tokens.
type Set struct {
	Home   string   `json:"home"`
	Tokens []Token  `json:"tokens"`
	Dirs   []string `json:"dirs"` // directories created for them (absolute)
}

// Generate makes a fresh set under home (an absolute path inside the sandbox).
func Generate(home string) (*Set, error) {
	if !path.IsAbs(home) || strings.ContainsRune(home, 0) {
		return nil, fmt.Errorf("honeytoken: home %q must be absolute", home)
	}
	home = path.Clean(home)
	s := &Set{Home: home}
	add := func(kind, rel string, content []byte, secrets ...string) error {
		id, err := randomString(alnum, 20)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(content)
		s.Tokens = append(s.Tokens, Token{ID: "ht_" + id, Kind: kind, Path: path.Join(home, rel), Content: content, SHA256: hex.EncodeToString(sum[:]), Secrets: secrets})
		for d := path.Dir(rel); d != "."; d = path.Dir(d) {
			s.addDir(path.Join(home, d))
		}
		return nil
	}

	key, keyLine, err := sshKey()
	if err != nil {
		return nil, err
	}
	keyID, err1 := randomString(upperDigits, 16)
	secret, err2 := randomString(base64Chars, 40)
	openai, err3 := randomString(alnum, 48)
	stripe, err4 := randomString(alnum, 32)
	gh, err5 := randomString(alnum, 36)
	sess, err6 := randomString(hexChars, 64)
	auth, err7 := randomString(hexChars, 40)
	if err := firstErr(err1, err2, err3, err4, err5, err6, err7); err != nil {
		return nil, err
	}
	akid := "AKIA" + keyID
	aws := fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\nregion = us-east-1\n", akid, secret)
	env := fmt.Sprintf("# production\nOPENAI_API_KEY=sk-proj-%s\nSTRIPE_SECRET_KEY=sk_live_%s\nGITHUB_TOKEN=ghp_%s\nDATABASE_URL=postgres://app:%s@db.internal:5432/app\n", openai, stripe, gh, stripe[:16])
	cookies, err := cookieDB([]cookie{
		{host: ".github.com", name: "user_session", value: sess},
		{host: ".amazon.com", name: "session-token", value: auth},
	})
	if err != nil {
		return nil, err
	}
	for _, e := range []error{
		add(KindSSHKey, ".ssh/id_ed25519", key, keyLine),
		add(KindAWS, ".aws/credentials", []byte(aws), akid, secret),
		add(KindEnv, ".env", []byte(env), "sk-proj-"+openai, "sk_live_"+stripe, "ghp_"+gh),
		add(KindCookies, ".config/google-chrome/Default/Cookies", cookies, sess, auth),
	} {
		if e != nil {
			return nil, e
		}
	}
	return s, nil
}

func (s *Set) addDir(d string) {
	for _, x := range s.Dirs {
		if x == d {
			return
		}
	}
	s.Dirs = append(s.Dirs, d)
}

// ByPath is the token planted at p, if any.
func (s *Set) ByPath(p string) (Token, bool) {
	for _, t := range s.Tokens {
		if t.Path == p {
			return t, true
		}
	}
	return Token{}, false
}

// Tar is the set as a tar stream rooted at Home (directories 0700, files 0600), for a
// backend's CopyIn, which makes everything the sandbox user's.
func (s *Set) Tar() (io.Reader, error) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	mt := time.Now().Add(-37 * 24 * time.Hour).Truncate(time.Second) // not "just created"
	dirs := append([]string(nil), s.Dirs...)
	sort.Slice(dirs, func(i, j int) bool { return len(dirs[i]) < len(dirs[j]) }) // parents first
	for _, d := range dirs {
		rel := strings.TrimPrefix(d, strings.TrimSuffix(s.Home, "/")+"/")
		if err := tw.WriteHeader(&tar.Header{Name: rel + "/", Typeflag: tar.TypeDir, Mode: 0o700, ModTime: mt}); err != nil {
			return nil, fmt.Errorf("honeytoken: %w", err)
		}
	}
	for _, t := range s.Tokens {
		rel := strings.TrimPrefix(t.Path, strings.TrimSuffix(s.Home, "/")+"/")
		if err := tw.WriteHeader(&tar.Header{Name: rel, Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(t.Content)), ModTime: mt}); err != nil {
			return nil, fmt.Errorf("honeytoken: %w", err)
		}
		if _, err := tw.Write(t.Content); err != nil {
			return nil, fmt.Errorf("honeytoken: %w", err)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("honeytoken: %w", err)
	}
	return &b, nil
}

// Save writes the set to path (0600).
func (s *Set) Save(p string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("honeytoken: %w", err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return fmt.Errorf("honeytoken: %w", err)
	}
	return nil
}

// Load reads a set saved with Save.
func Load(p string) (*Set, error) {
	b, err := os.ReadFile(p) //nolint:gosec // G304: qtd's own workspace file
	if err != nil {
		return nil, fmt.Errorf("honeytoken: %w", err)
	}
	var s Set
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("honeytoken: %s: %w", p, err)
	}
	return &s, nil
}

// sshKey is a fake OpenSSH private key and one of its base64 lines (the secret to watch for).
func sshKey() ([]byte, string, error) {
	body := make([]byte, 399) // the size of a real ed25519 openssh-key-v1 blob
	if _, err := rand.Read(body); err != nil {
		return nil, "", fmt.Errorf("honeytoken: %w", err)
	}
	copy(body, "openssh-key-v1\x00\x00\x00\x00\x04none\x00\x00\x00\x04none\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x33\x00\x00\x00\x0bssh-ed25519")
	enc := base64.StdEncoding.EncodeToString(body)
	var lines []string
	for len(enc) > 70 {
		lines = append(lines, enc[:70])
		enc = enc[70:]
	}
	lines = append(lines, enc)
	key := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + strings.Join(lines, "\n") + "\n-----END OPENSSH PRIVATE KEY-----\n"
	return []byte(key), lines[2], nil // line 3: past the fixed header, all random
}

const (
	alnum       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	upperDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	base64Chars = alnum + "+/"
	hexChars    = "0123456789abcdef"
)

func randomString(alphabet string, n int) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("honeytoken: %w", err)
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out), nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
