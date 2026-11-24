package report

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/Frostykiller3m/Quaarant/internal/events"
)

// Rules are the findings that need no judgment.
func Rules(evs []events.Event) []Finding {
	var r ruleSet
	for _, ev := range evs {
		r.see(ev)
	}
	return r.findings()
}

type ruleSet struct {
	honeyRead, honeyOut    []string
	persistence            []string
	persistPaths           []string
	minerExec, minerNet    []string
	metadata, bypass       []string
	refusedTargets         map[string]bool
	refused                []string
	dnsData                []string
	tmpExec, pipeShell     []string
	bigUpload              []string
	honeyKinds, honeyDst   []string
	minerWhat, tmpWhat     []string
	uploadWhat, bypassWhat []string
	pipeWhat, dnsWhat      []string
}

// Persistence locations: shell start-up files, cron, systemd/init, autostart, SSH keys, the
// dynamic loader, git hooks, macOS launch agents.
var persistRe = regexp.MustCompile(`(^|/)(\.bashrc|\.bash_profile|\.bash_login|\.profile|\.zshrc|\.zprofile|\.config/fish/config\.fish)$` +
	`|^/etc/(cron\.[a-z]+/|crontab$|profile\.d/|rc\.local$|init\.d/|systemd/system/|ld\.so\.preload$)` +
	`|^/var/spool/cron/|^/usr/lib/systemd/|(^|/)\.config/(autostart|systemd/user)/` +
	`|(^|/)\.ssh/(authorized_keys2?|rc)$|(^|/)\.git/hooks/|(^|/)Library/LaunchAgents/`)

var minerRe = regexp.MustCompile(`(?i)\b(xmrig|xmr-stak|minerd|cpuminer|ethminer|nbminer|t-rex|lolminer|phoenixminer|nanominer)\b|stratum\+(tcp|ssl)://|--donate-level|--coin[= ](xmr|monero)`)

var minerDNSRe = regexp.MustCompile(`(?i)(^|\.)(pool|mining|miner|xmr|monero|nicehash|2miners|f2pool|supportxmr|nanopool|ethermine|minexmr|hashvault)[.-]`)

var minerPorts = map[int]bool{3333: true, 4444: true, 5555: true, 7777: true, 14433: true, 14444: true, 45700: true}

var pipeShellRe = regexp.MustCompile(`(curl|wget)\b[^|;&]*\|\s*(ba|z|da)?sh\b|(curl|wget)\b[^|;&]*-[a-zA-Z]*O-[^|;&]*\|\s*(ba|z|da)?sh\b`)

var dataLabelRe = regexp.MustCompile(`^[a-z0-9]{40,}$|^[a-f0-9]{32,}$`)

func (r *ruleSet) see(ev events.Event) {
	switch ev.Kind {
	case events.KindHoneytoken:
		var h events.Honeytoken
		if json.Unmarshal(ev.Data, &h) != nil {
			return
		}
		if h.Trigger == "read" {
			r.honeyRead = append(r.honeyRead, ev.ID)
			r.honeyKinds = addUnique(r.honeyKinds, h.TokenKind)
		} else {
			r.honeyOut = append(r.honeyOut, ev.ID)
			r.honeyDst = addUnique(r.honeyDst, h.TokenKind+" → "+h.Dst)
		}
	case events.KindFile:
		var f events.File
		if json.Unmarshal(ev.Data, &f) != nil || f.Errno != "" {
			return
		}
		target := f.Path
		if f.Op == "rename" {
			target = f.NewPath // what lands at a persistence path counts, not what leaves one
		}
		switch f.Op {
		case "create", "write", "rename", "chmod", "symlink", "mkdir":
			if persistRe.MatchString(target) {
				r.persistence = append(r.persistence, ev.ID)
				r.persistPaths = addUnique(r.persistPaths, target)
			}
		}
	case events.KindExec:
		var x events.Exec
		if json.Unmarshal(ev.Data, &x) != nil {
			return
		}
		cmd := strings.Join(x.Argv, " ")
		switch {
		case minerRe.MatchString(x.Path) || minerRe.MatchString(cmd):
			r.minerExec = append(r.minerExec, ev.ID)
			r.minerWhat = addUnique(r.minerWhat, short(cmd, 120))
		case x.Path != "" && (strings.HasPrefix(x.Path, "/tmp/") || strings.HasPrefix(x.Path, "/dev/shm/") || strings.HasPrefix(x.Path, "/var/tmp/")):
			r.tmpExec = append(r.tmpExec, ev.ID)
			r.tmpWhat = addUnique(r.tmpWhat, x.Path)
		}
		base := path.Base(x.Path)
		if len(x.Argv) > 0 { // busybox applets: the binary is busybox, argv[0] the applet
			base = path.Base(x.Argv[0])
		}
		if (base == "crontab" && len(x.Argv) > 1 && x.Argv[1] != "-l") || (base == "systemctl" && strings.Contains(cmd, " enable")) {
			r.persistence = append(r.persistence, ev.ID)
			r.persistPaths = addUnique(r.persistPaths, short(cmd, 80))
		}
		if pipeShellRe.MatchString(cmd) {
			r.pipeShell = append(r.pipeShell, ev.ID)
			r.pipeWhat = addUnique(r.pipeWhat, short(cmd, 120))
		}
	case events.KindNet:
		var n events.Net
		if json.Unmarshal(ev.Data, &n) != nil {
			return
		}
		if n.Op == "connect" && minerPorts[n.DstPort] && (n.Allowed == nil || *n.Allowed) {
			r.minerNet = append(r.minerNet, ev.ID)
			r.minerWhat = addUnique(r.minerWhat, fmt.Sprintf("%s:%d", orDefault(n.SNI, n.DstIP), n.DstPort))
		}
		if n.Op == "close" && n.BytesOut != nil && *n.BytesOut > 10<<20 {
			r.bigUpload = append(r.bigUpload, ev.ID)
			r.uploadWhat = addUnique(r.uploadWhat, fmt.Sprintf("%s (%d MiB)", orDefault(n.SNI, orDefault(n.HTTPHost, n.DstIP)), *n.BytesOut>>20))
		}
	case events.KindDNS:
		var d events.DNS
		if json.Unmarshal(ev.Data, &d) != nil {
			return
		}
		if minerDNSRe.MatchString(d.QName) {
			r.minerNet = append(r.minerNet, ev.ID)
			r.minerWhat = addUnique(r.minerWhat, d.QName)
		}
		for _, l := range strings.Split(d.QName, ".") {
			if dataLabelRe.MatchString(l) {
				r.dnsData = append(r.dnsData, ev.ID)
				r.dnsWhat = addUnique(r.dnsWhat, short(d.QName, 100))
				break
			}
		}
	case events.KindPolicyDenied:
		var p events.PolicyDenied
		if json.Unmarshal(ev.Data, &p) != nil {
			return
		}
		switch p.Reason {
		case "metadata":
			r.metadata = append(r.metadata, ev.ID)
		case "direct_ip", "sni_mismatch":
			r.bypass = append(r.bypass, ev.ID)
			r.bypassWhat = addUnique(r.bypassWhat, short(p.Target, 80)+" ("+p.Reason+")")
		}
		if r.refusedTargets == nil {
			r.refusedTargets = map[string]bool{}
		}
		r.refusedTargets[p.Target] = true
		r.refused = append(r.refused, ev.ID)
	}
}

func (r *ruleSet) findings() []Finding {
	var out []Finding
	add := func(ids []string, title, sev, cat, expl string) {
		if len(ids) == 0 {
			return
		}
		out = append(out, Finding{Title: title, Severity: sev, Category: cat, Evidence: capIDs(ids), Explanation: expl, Source: "rules"})
	}
	add(r.honeyOut, "A planted credential left the sandbox", Critical, "exfiltration",
		"A fake credential qt planted turned up in outbound DNS, TLS SNI or plaintext: "+list(r.honeyDst)+". Nothing legitimate sends these.")
	add(r.honeyRead, "Planted credentials were read", High, "honeytoken",
		"A process opened fake credentials qt planted in $HOME ("+list(r.honeyKinds)+"). Code that looks for credentials it was not given is a classic stealer behaviour.")
	add(r.minerExec, "A cryptocurrency miner ran", Critical, "miner", "Miner binary or arguments: "+list(r.minerWhat)+".")
	if len(r.minerExec) == 0 {
		add(r.minerNet, "Mining pool traffic", Medium, "miner", "Lookups or connections that look like a mining pool: "+list(r.minerWhat)+".")
	}
	add(r.persistence, "Wrote to persistence locations", High, "persistence",
		"Changes that make code run again later (shell start-up, cron, services, SSH keys, hooks): "+list(r.persistPaths)+".")
	add(r.metadata, "Probed the cloud metadata service", High, "network",
		"Connections to the instance-metadata address, where cloud credentials live. qt refused them.")
	add(r.bypass, "Tried to get around the network allow-list", Medium, "network",
		"Connections to addresses the resolver never returned, or with a TLS name or HTTP Host outside the allow-list: "+list(r.bypassWhat)+".")
	if len(r.refusedTargets) >= 10 {
		add(r.refused, "Many refused destinations", Medium, "network",
			fmt.Sprintf("%d distinct destinations were refused: scanning, or looking for a way out.", len(r.refusedTargets)))
	}
	add(r.dnsData, "Data-like DNS names", Medium, "exfiltration", "DNS names with long encoded-looking labels, a common way to smuggle data out: "+list(r.dnsWhat)+".")
	add(r.pipeShell, "Downloaded and ran a script", Medium, "execution", "A download piped straight into a shell: "+list(r.pipeWhat)+".")
	add(r.tmpExec, "Ran a program from a temporary directory", Medium, "execution", "Executables run from /tmp, /var/tmp or /dev/shm: "+list(r.tmpWhat)+".")
	add(r.bigUpload, "Large upload", Low, "exfiltration", "Over 10 MiB sent to "+list(r.uploadWhat)+".")
	sortFindings(out)
	return out
}

func addUnique(xs []string, x string) []string {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	if len(xs) >= 8 {
		return xs
	}
	return append(xs, x)
}

func capIDs(ids []string) []string {
	if len(ids) > 20 {
		return ids[:20]
	}
	return ids
}

func list(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = clean(x, 160)
	}
	return strings.Join(q, ", ")
}

func short(s string, n int) string { return clean(s, n) }
