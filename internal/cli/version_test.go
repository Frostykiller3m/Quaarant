package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Frostykiller3m/Quaarant/internal/version"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	root := NewRootCommand(&out, &errOut)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestVersionCommand(t *testing.T) {
	old := version.Version
	t.Cleanup(func() { version.Version = old })
	version.Version = "v9.9.9-test"

	t.Run("text", func(t *testing.T) {
		out, err := run(t, "version")
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"qt v9.9.9-test\n", "commit:", "built:", "go:", "platform:"} {
			if !strings.Contains(out, want) {
				t.Errorf("output missing %q:\n%s", want, out)
			}
		}
	})

	t.Run("json", func(t *testing.T) {
		out, err := run(t, "version", "--json")
		if err != nil {
			t.Fatal(err)
		}
		var info version.Info
		if err := json.Unmarshal([]byte(out), &info); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, out)
		}
		if info.Version != "v9.9.9-test" || info.Platform == "" || info.GoVersion == "" {
			t.Errorf("unexpected info: %+v", info)
		}
	})

	t.Run("rejects args", func(t *testing.T) {
		if _, err := run(t, "version", "extra"); err == nil {
			t.Fatal("expected error for extra argument")
		}
	})
}

func TestUnknownCommand(t *testing.T) {
	if _, err := run(t, "nope"); err == nil {
		t.Fatal("expected error for unknown command")
	}
}
