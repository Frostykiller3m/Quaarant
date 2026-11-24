package cli

import (
	"slices"
	"strings"
	"testing"
)

func TestParseBytes(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
		err  bool
	}{
		{"512m", 512 << 20, false},
		{"2g", 2 << 30, false},
		{"2G", 2 << 30, false},
		{"1.5g", 3 << 29, false},
		{"64mb", 64 << 20, false},
		{"1048576", 1 << 20, false},
		{"", 0, true},
		{"-1m", 0, true},
		{"lots", 0, true},
		{"99999t", 0, true},
	}
	for _, tt := range tests {
		got, err := parseBytes(tt.in)
		if (err != nil) != tt.err || got != tt.want {
			t.Errorf("parseBytes(%q) = %d, %v", tt.in, got, err)
		}
	}
}

func TestSplitCommand(t *testing.T) {
	tests := []struct {
		args []string
		head string
		rest []string
	}{
		{[]string{"alpine", "--", "sh", "-c", "echo hi"}, "alpine", []string{"sh", "-c", "echo hi"}},
		{[]string{"alpine", "sh"}, "alpine", []string{"sh"}},
		{[]string{"alpine"}, "alpine", []string{}},
		{[]string{"alpine", "--", "--", "x"}, "alpine", []string{"--", "x"}},
	}
	for _, tt := range tests {
		h, r := splitCommand(tt.args)
		if h != tt.head || !slices.Equal(r, tt.rest) {
			t.Errorf("splitCommand(%q) = %q %q", tt.args, h, r)
		}
	}
}

func TestCreateRequestFlags(t *testing.T) {
	req, err := createRequest("alpine", "gvisor", "none", "", "512m", 1.5, 100, []string{"a=b"})
	if err != nil {
		t.Fatal(err)
	}
	if req.GetLimits().GetCpuMillis() != 1500 || req.GetLimits().GetMemoryBytes() != 512<<20 || req.GetLimits().GetPids() != 100 || req.GetLabels()["a"] != "b" {
		t.Errorf("req = %v", req)
	}
	for _, bad := range []func() error{
		func() error { _, err := createRequest("x", "docker", "none", "", "", 0, 0, nil); return err },
		func() error { _, err := createRequest("x", "gvisor", "allow:", "", "", 0, 0, nil); return err },
		func() error { _, err := createRequest("x", "gvisor", "open", "", "", 0, 0, nil); return err },
		func() error { _, err := createRequest("x", "gvisor", "none", "", "", -1, 0, nil); return err },
		func() error { _, err := createRequest("x", "gvisor", "none", "", "1q", 0, 0, nil); return err },
		func() error {
			_, err := createRequest("x", "gvisor", "none", "", "", 0, 0, []string{"novalue"})
			return err
		},
	} {
		if bad() == nil {
			t.Error("bad flags accepted")
		}
	}
}

func TestParseNet(t *testing.T) {
	for in, want := range map[string]string{
		"none":                                   "mode:MODE_NONE",
		"log":                                    "mode:MODE_LOG",
		"allow:pypi.org":                         `mode:MODE_ALLOW allow_domains:"pypi.org"`,
		"allow:pypi.org, files.pythonhosted.org": `mode:MODE_ALLOW allow_domains:"pypi.org" allow_domains:"files.pythonhosted.org"`,
	} {
		np, err := parseNet(in)
		if err != nil || strings.Join(strings.Fields(np.String()), " ") != want {
			t.Errorf("parseNet(%q) = %v, %v; want %s", in, np, err, want)
		}
	}
}
