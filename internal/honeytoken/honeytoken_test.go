package honeytoken

import (
	"archive/tar"
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	a, err := Generate("/home/app")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate("/home/app")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for i, tok := range a.Tokens {
		kinds[tok.Kind] = tok.Path
		if !strings.HasPrefix(tok.ID, "ht_") || len(tok.Secrets) == 0 {
			t.Errorf("token %+v", tok)
		}
		for _, s := range tok.Secrets {
			if len(s) < minSecretLen || !bytes.Contains(tok.Content, []byte(s)) {
				t.Errorf("%s: secret %q not in its file", tok.Kind, s)
			}
			for _, o := range b.Tokens[i].Secrets {
				if s == o {
					t.Errorf("%s: two sandboxes got the same secret", tok.Kind)
				}
			}
		}
	}
	want := map[string]string{
		KindSSHKey: "/home/app/.ssh/id_ed25519", KindAWS: "/home/app/.aws/credentials",
		KindEnv: "/home/app/.env", KindCookies: "/home/app/.config/google-chrome/Default/Cookies",
	}
	for k, p := range want {
		if kinds[k] != p {
			t.Errorf("%s at %q, want %q", k, kinds[k], p)
		}
	}
	if _, err := Generate("relative"); err == nil {
		t.Error("relative home accepted")
	}
}

func TestTarAndSave(t *testing.T) {
	s, _ := Generate("/tmp")
	r, err := s.Tar()
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(r)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Typeflag == tar.TypeReg && h.Mode != 0o600 || h.Typeflag == tar.TypeDir && h.Mode != 0o700 {
			t.Errorf("%s mode %o", h.Name, h.Mode)
		}
	}
	got := strings.Join(names, ",")
	if !strings.HasPrefix(got, ".ssh/,.aws/,.config/,") || !strings.Contains(got, ".config/google-chrome/Default/Cookies") || strings.Contains(got, "/tmp") {
		t.Errorf("tar entries %s", got)
	}
	p := filepath.Join(t.TempDir(), "h.json")
	if err := s.Save(p); err != nil {
		t.Fatal(err)
	}
	l, err := Load(p)
	if err != nil || len(l.Tokens) != 4 || l.Tokens[0].SHA256 != s.Tokens[0].SHA256 {
		t.Errorf("load: %v %+v", err, l)
	}
	if tok, ok := l.ByPath("/tmp/.aws/credentials"); !ok || tok.Kind != KindAWS {
		t.Errorf("ByPath: %+v %v", tok, ok)
	}
}

func TestCookieDB(t *testing.T) {
	db, err := cookieDB([]cookie{{".github.com", "user_session", strings.Repeat("ab", 32)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(db) != 2*pageSize || string(db[:16]) != "SQLite format 3\x00" || binary.BigEndian.Uint32(db[28:]) != 2 || db[100] != 0x0d || db[pageSize] != 0x0d {
		t.Fatalf("header %x", db[:110])
	}
	if !bytes.Contains(db, []byte(strings.Repeat("ab", 32))) || !bytes.Contains(db, []byte("CREATE TABLE cookies(")) {
		t.Error("contents missing")
	}
	// If a sqlite3 is around, it must open the file and find the row.
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("no python3 to check the file with sqlite3")
	}
	p := filepath.Join(t.TempDir(), "Cookies")
	if err := os.WriteFile(p, db, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(py, "-c", `import sqlite3,sys
c = sqlite3.connect(sys.argv[1])
print(c.execute("pragma integrity_check").fetchone()[0])
for r in c.execute("select host_key, name, length(value), is_secure, expires_utc > creation_utc from cookies"): print(*r)`, p).CombinedOutput()
	if err != nil || string(out) != "ok\n.github.com user_session 64 1 1\n" {
		t.Errorf("sqlite3: %v %q", err, out)
	}
}

func TestMatcher(t *testing.T) {
	s, _ := Generate("/tmp")
	m := NewMatcher(s)
	aws := s.Tokens[1]
	secret := aws.Secrets[1]
	tests := []struct {
		name string
		data string
		want string // token id, or ""
	}{
		{"raw in a POST body", "POST /c HTTP/1.1\r\n\r\nk=" + secret + "&x=1", aws.ID},
		{"hex", "q=" + hex.EncodeToString([]byte("aws="+secret+";")), aws.ID},
		{"base64 at offset 0", base64.StdEncoding.EncodeToString([]byte(secret)), aws.ID},
		{"base64 inside a blob", base64.StdEncoding.EncodeToString([]byte("[default]\nsecret=" + secret + "\n")), aws.ID},
		{"base64url inside a blob", base64.URLEncoding.EncodeToString([]byte("xx" + secret + "yy")), aws.ID},
		{"the whole file", string(aws.Content), aws.ID},
		{"nothing", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", ""},
	}
	for _, tt := range tests {
		hits := m.Find([]byte(tt.data))
		if (tt.want == "") != (len(hits) == 0) || (tt.want != "" && hits[0].TokenID != tt.want) {
			t.Errorf("%s: %v", tt.name, hits)
		}
	}
	// DNS: lowercased, split over labels, base32.
	akid := aws.Secrets[0]
	for _, name := range []string{
		strings.ToLower(akid) + ".evil.example",
		strings.ToLower(akid[:10]) + "." + strings.ToLower(akid[10:]) + ".evil.example",
		strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString([]byte(akid)), "=")) + ".x.example",
	} {
		if hits := m.FindName(name); len(hits) != 1 || hits[0].Kind != KindAWS {
			t.Errorf("FindName(%s) = %v", name, hits)
		}
	}
	if hits := m.FindName("pypi.org"); len(hits) != 0 {
		t.Errorf("false positive: %v", hits)
	}
	// A stream finds a secret split across writes, once.
	st := m.NewStream()
	body := "data=" + secret + "&again=" + secret
	var found []Hit
	for i := 0; i < len(body); i += 7 {
		found = append(found, st.Write([]byte(body[i:min(i+7, len(body))]))...)
	}
	if len(found) != 1 || found[0].TokenID != aws.ID {
		t.Errorf("stream: %v", found)
	}
	var nm *Matcher
	if nm.Find([]byte(secret)) != nil || nm.NewStream().Write([]byte(secret)) != nil {
		t.Error("nil matcher")
	}
}
