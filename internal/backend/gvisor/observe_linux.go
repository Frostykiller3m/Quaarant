//go:build linux

package gvisor

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/workspace"
)

// observer is everything that watches one sandbox from the host: gVisor runtime monitoring
// (exec, open, write, connect, with pids) and an inotify watcher on upper/ (unlink, rename,
// mkdir, symlink, create, chmod, which runsc reports without paths).
type observer struct {
	mon         *monitor
	sink        backend.EventSink
	watch       *workspace.Watcher
	traceConfig string
}

func startObserver(s backend.Spec, log *slog.Logger) (*observer, error) {
	mon, err := startMonitor(s.Workspace, s.Events, s.Network.None, log)
	if err != nil {
		return nil, err
	}
	cfg, err := traceConfig(filepath.Join(s.Workspace, monitorSocket))
	if err != nil {
		mon.stop()
		return nil, err
	}
	o := &observer{mon: mon, sink: s.Events, traceConfig: filepath.Join(bundleDir(s.Workspace), traceConfigFile)}
	if err := os.WriteFile(o.traceConfig, cfg, 0o600); err != nil {
		mon.stop()
		return nil, fmt.Errorf("write trace config: %w", err)
	}
	sink := s.Events
	o.watch, err = workspace.Watch(filepath.Join(s.Workspace, "upper"), s.RootFS,
		workspace.WatchOptions{Hidden: []string{qtDir}},
		func(fe workspace.FileEvent) { _ = sink.Emit(context.Background(), events.SourceHost, fileEvent(fe)) })
	if err != nil {
		mon.stop()
		return nil, err
	}
	return o, nil
}

// ready waits for runsc to have connected the monitoring stream (runsc create did it).
func (o *observer) ready() error { return o.mon.waitReady(30 * time.Second) }

func (o *observer) stop() {
	o.mon.stop()
	_ = o.watch.Close()
}

// suppress hides qt's own changes under dir (qt cp) from the watcher.
func (o *observer) suppress(dir string) func() { return o.watch.Suppress(dir) }

func fileEvent(fe workspace.FileEvent) events.File {
	ev := events.File{Op: fe.Op, Path: boundPath(fe.Path)}
	if fe.NewPath != "" {
		ev.NewPath = boundPath(fe.NewPath)
	}
	switch {
	case fe.Mode == 0:
	case fe.Op == "create", fe.Op == "mkdir", fe.Op == "chmod":
		m := uint32(fe.Mode.Perm())
		if fe.Mode&fs.ModeSetuid != 0 {
			m |= 0o4000
		}
		if fe.Mode&fs.ModeSetgid != 0 {
			m |= 0o2000
		}
		if fe.Mode&fs.ModeSticky != 0 {
			m |= 0o1000
		}
		ev.Mode = fmt.Sprintf("0%03o", m)
	}
	return ev
}

// launched records a process qtd started with runsc exec (the sentry reports no execve for
// it). Observed by qtd itself: source host.
func (o *observer) launched(pid int, p *specs.Process) {
	ev := events.Exec{PID: boundPID(int32(min(pid, 1<<31-1))), PPID: 0, Argv: []string{}} //nolint:gosec // G115: clamped
	if len(p.Args) > 0 {
		ev.Path = boundPath(p.Args[0])
	}
	if ev.Path == "" {
		return
	}
	for i, a := range p.Args {
		if i == maxArgs {
			ev.ArgvTruncated = true
			break
		}
		if len(a) > maxArgLen {
			a, ev.ArgvTruncated = truncate(a, maxArgLen), true
		}
		ev.Argv = append(ev.Argv, a)
	}
	if cwd := boundPath(p.Cwd); strings.HasPrefix(cwd, "/") {
		ev.Cwd = cwd
	}
	uid := p.User.UID
	ev.UID = &uid
	_ = o.sink.Emit(context.Background(), events.SourceHost, ev)
}
