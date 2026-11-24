package report

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

// Bounds on what goes to Claude.
const (
	maxLines = 1500
	maxBytes = 300 << 10
)

// line is one compacted entry: the first event of a group, how many it stands for, and (for
// execs) the depth in the process tree.
type line struct {
	ID     string          `json:"id"`
	Kind   events.Kind     `json:"kind"`
	Source events.Source   `json:"source"`
	Count  int             `json:"count,omitempty"`
	Depth  int             `json:"depth,omitempty"`
	Data   json.RawMessage `json:"data"`
}

// Compacted is a log made small enough to read: repeats collapsed, the noise of loading
// programs dropped, execs ordered as a process tree. Red flags (honeytoken and policy_denied
// events) are always kept.
type Compacted struct {
	Lines   []line
	Omitted int // events left out to stay within bounds (never red flags)
}

const perDirMax = 8

func fileOpDir(ev events.Event) string {
	var f events.File
	if json.Unmarshal(ev.Data, &f) != nil {
		return ""
	}
	return f.Op + "|" + path.Dir(f.Path)
}

// noisy are opens of the system's own files: every program does them.
var noisyPrefixes = []string{"/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/share/", "/etc/ld.so.", "/proc/", "/sys/", "/dev/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/lib/"}

// Compact builds the compacted view of evs (in log order).
func Compact(evs []events.Event) Compacted {
	var red, rest []line
	groups := map[string]int{} // key -> index in rest
	perDir := map[string]int{} // file op + directory -> distinct paths seen
	var execs []events.Event
	for _, ev := range evs {
		switch ev.Kind {
		case events.KindHoneytoken, events.KindPolicyDenied:
			red = append(red, line{ID: ev.ID, Kind: ev.Kind, Source: ev.Source, Data: ev.Data})
			continue
		case events.KindExec:
			execs = append(execs, ev)
			continue
		}
		key := groupKey(ev)
		if key == "" {
			continue
		}
		if _, seen := groups[key]; !seen && ev.Kind == events.KindFile {
			// Past perDirMax distinct paths, one directory's operations of one kind become a
			// single counted line (package installs write thousands of files).
			if d := fileOpDir(ev); d != "" {
				perDir[d]++
				if perDir[d] > perDirMax {
					key = "dir|" + d
				}
			}
		}
		if i, ok := groups[key]; ok {
			rest[i].Count++
			continue
		}
		groups[key] = len(rest)
		rest = append(rest, line{ID: ev.ID, Kind: ev.Kind, Source: ev.Source, Count: 1, Data: ev.Data})
	}
	tree := execTree(execs)
	out := Compacted{}
	budget := maxBytes
	add := func(l line, force bool) bool {
		if l.Count == 1 {
			l.Count = 0
		}
		b, _ := json.Marshal(l)
		if !force && (len(out.Lines) >= maxLines || budget-len(b) < 0) {
			out.Omitted++
			return false
		}
		budget -= len(b)
		out.Lines = append(out.Lines, l)
		return true
	}
	for _, l := range red {
		add(l, true)
	}
	for _, l := range tree {
		add(l, false)
	}
	for _, l := range rest {
		add(l, false)
	}
	return out
}

// groupKey identifies repeats ("" = drop the event).
func groupKey(ev events.Event) string {
	switch ev.Kind {
	case events.KindFile:
		var f events.File
		if json.Unmarshal(ev.Data, &f) != nil {
			return ""
		}
		// Programs loading their own system files, or probing for ones that aren't there
		// (Python's .pyc lookups): noise. A denied open (EACCES) stays.
		if f.Op == "open" && (f.Errno == "" || f.Errno == "ENOENT" || f.Errno == "ENOTDIR") {
			for _, p := range noisyPrefixes {
				if strings.HasPrefix(f.Path, p) {
					return ""
				}
			}
		}
		return "file|" + f.Op + "|" + f.Path + "|" + f.NewPath + "|" + f.Errno
	case events.KindNet:
		var n events.Net
		if json.Unmarshal(ev.Data, &n) != nil {
			return ""
		}
		return fmt.Sprintf("net|%s|%s|%d|%s|%s|%v", n.Op, n.DstIP, n.DstPort, n.SNI, n.HTTPHost, n.Allowed != nil && *n.Allowed)
	case events.KindDNS:
		var d events.DNS
		if json.Unmarshal(ev.Data, &d) != nil {
			return ""
		}
		return fmt.Sprintf("dns|%s|%s|%v", d.QName, d.QType, d.Allowed)
	}
	return string(ev.Kind) + "|" + string(ev.Data)
}

// execTree orders execs depth-first from the roots (processes whose parent did not exec in
// the log), collapsing identical commands under the same parent.
func execTree(execs []events.Event) []line {
	type node struct {
		ev   events.Event
		x    events.Exec
		kids []int
	}
	nodes := make([]node, 0, len(execs))
	byPID := map[int]int{}
	for _, ev := range execs {
		var x events.Exec
		if json.Unmarshal(ev.Data, &x) != nil {
			continue
		}
		nodes = append(nodes, node{ev: ev, x: x})
		byPID[x.PID] = len(nodes) - 1 // the latest exec of a pid
	}
	var roots []int
	for i := range nodes {
		p, ok := byPID[nodes[i].x.PPID]
		if ok && p < i && nodes[i].x.PPID != nodes[i].x.PID {
			nodes[p].kids = append(nodes[p].kids, i)
		} else {
			roots = append(roots, i)
		}
	}
	var out []line
	var walk func(ids []int, depth int)
	walk = func(ids []int, depth int) {
		seen := map[string]int{} // command -> index in out
		for _, i := range ids {
			n := nodes[i]
			key := n.x.Path + "\x00" + strings.Join(n.x.Argv, "\x00")
			if j, ok := seen[key]; ok && len(n.kids) == 0 {
				out[j].Count++
				continue
			}
			seen[key] = len(out)
			out = append(out, line{ID: n.ev.ID, Kind: events.KindExec, Source: n.ev.Source, Count: 1, Depth: min(depth, 32), Data: n.ev.Data})
			if depth < 64 {
				walk(n.kids, depth+1)
			}
		}
	}
	walk(roots, 0)
	return slices.Clip(out)
}

// Render writes the compacted log as JSON lines. Every value is JSON-encoded with HTML
// escaping, so sandbox text can never contain a literal '<', '>' or '&' and can't close the
// tag the prompt wraps it in.
func (c Compacted) Render() string {
	var b strings.Builder
	for _, l := range c.Lines {
		raw, _ := json.Marshal(l) // json.Marshal escapes <, > and & as \u003c, \u003e, \u0026
		b.Write(raw)
		b.WriteByte('\n')
	}
	return b.String()
}
