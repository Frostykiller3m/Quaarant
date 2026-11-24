package daemon

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/backend/gvisor"
	"github.com/Frostykiller3m/Quaarant/internal/image"
	"github.com/Frostykiller3m/Quaarant/internal/version"
)

// Defaults for a system install.
const (
	DefaultSocket  = "/run/quarantine/qtd.sock"
	DefaultDataDir = "/var/lib/quarantine"
	DefaultGroup   = "quarantine"
)

// Listen creates the unix socket (replacing a stale one), sets it to 0660 root:<group>, and
// returns it with the authorizer for its peers. If the group does not exist only root (and
// the daemon's own uid) may connect.
func Listen(socket, group string, log *slog.Logger) (net.Listener, Authorizer, error) {
	if err := os.MkdirAll(filepath.Dir(socket), 0o755); err != nil { //nolint:gosec // G301: group members must reach the socket inside
		return nil, nil, fmt.Errorf("create socket dir: %w", err)
	}
	if fi, err := os.Lstat(socket); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, nil, fmt.Errorf("%s exists and is not a socket", socket)
		}
		if err := os.Remove(socket); err != nil {
			return nil, nil, fmt.Errorf("remove stale socket: %w", err)
		}
	}
	lis, err := net.Listen("unix", socket)
	if err != nil {
		return nil, nil, fmt.Errorf("listen on %s: %w", socket, err)
	}
	if ul, ok := lis.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}
	mode := os.FileMode(0o600)
	var gid uint32
	haveGroup := false
	if g, err := user.LookupGroup(group); err == nil {
		if n, err := strconv.ParseUint(g.Gid, 10, 32); err == nil {
			gid, haveGroup, mode = uint32(n), true, 0o660
			if err := os.Chown(socket, -1, int(n)); err != nil {
				_ = lis.Close()
				return nil, nil, fmt.Errorf("chown socket: %w", err)
			}
		}
	} else {
		log.Warn("group not found; only root may use qtd", "group", group)
	}
	if err := os.Chmod(socket, mode); err != nil {
		_ = lis.Close()
		return nil, nil, fmt.Errorf("chmod socket: %w", err)
	}
	return lis, GroupAuthorizer(gid, haveGroup, uint32(os.Geteuid())), nil //nolint:gosec // G115: euid fits
}

// Serve runs the gRPC server on lis until ctx is done.
func Serve(ctx context.Context, lis net.Listener, svc *Service, authorize Authorizer) error {
	g := grpc.NewServer(grpc.Creds(PeerCredentials(authorize)), grpc.MaxRecvMsgSize(4<<20))
	svc.Register(g)
	errc := make(chan error, 1)
	go func() { errc <- g.Serve(lis) }()
	select {
	case err := <-errc:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	stopped := make(chan struct{})
	go func() { g.GracefulStop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		g.Stop()
	}
	return nil
}

// Main is qtd's entry point; it returns the process exit code.
func Main(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("qtd", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var (
		showVersion  = fl.Bool("version", false, "print version and exit")
		socket       = fl.String("socket", DefaultSocket, "unix socket to listen on")
		dataDir      = fl.String("data-dir", DefaultDataDir, "data directory (images, sandboxes)")
		group        = fl.String("group", DefaultGroup, "group whose members may use qtd")
		runsc        = fl.String("runsc", "runsc", "runsc binary")
		runscRoot    = fl.String("runsc-root", "/run/quarantine/runsc", "runsc state directory")
		agent        = fl.String("agent", "", "static qt-agent binary (default: next to qtd, then /usr/local/lib/quarantine/qt-agent)")
		cgroupParent = fl.String("cgroup-parent", "/quarantine", "cgroup v2 parent for sandboxes")
		debug        = fl.Bool("debug", false, "debug logging")
	)
	if err := fl.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, version.Get().String("qtd"))
		return 0
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	if err := run(log, *socket, *dataDir, *group, *runsc, *runscRoot, *agent, *cgroupParent); err != nil {
		log.Error("qtd failed", "err", err)
		return 1
	}
	return 0
}

func run(log *slog.Logger, socket, dataDir, group, runsc, runscRoot, agent, cgroupParent string) error {
	if os.Geteuid() != 0 {
		return errors.New("qtd must run as root (it mounts overlays and manages cgroups)")
	}
	var backends []backend.Backend
	if path, err := exec.LookPath(runsc); err != nil {
		log.Warn("runsc not found; gvisor isolation unavailable", "runsc", runsc)
	} else {
		agentPath, err := findAgent(agent)
		if err != nil {
			return err
		}
		b, err := gvisor.New(gvisor.Config{Runsc: path, StateDir: runscRoot, AgentPath: agentPath, CgroupParent: cgroupParent})
		if err != nil {
			return fmt.Errorf("gvisor backend: %w", err)
		}
		backends = append(backends, b)
		log.Info("backend ready", "isolation", b.Name(), "runsc", path, "agent", agentPath)
	}
	svc, err := New(Options{
		DataDir: dataDir, Backends: backends, Images: image.NewStore(filepath.Join(dataDir, "images")), Logger: log,
	})
	if err != nil {
		return err
	}
	lis, authorize, err := Listen(socket, group, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	log.Info("qtd listening", "socket", socket, "data_dir", dataDir, "version", version.Get().Version)
	return Serve(ctx, lis, svc, authorize)
}

func findAgent(flagValue string) (string, error) {
	candidates := []string{flagValue}
	if flagValue == "" {
		if exe, err := os.Executable(); err == nil {
			candidates = []string{filepath.Join(filepath.Dir(exe), "qt-agent"), "/usr/local/lib/quarantine/qt-agent"}
		}
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if fi, err := os.Stat(abs); err == nil && fi.Mode().IsRegular() {
			return abs, nil
		}
	}
	return "", fmt.Errorf("qt-agent binary not found (tried %v); build it with `make build-linux` or pass --agent", candidates)
}
