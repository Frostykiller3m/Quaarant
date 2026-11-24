//go:build linux

package agent

import (
	"os"
	"os/signal"
	"syscall"
)

func ignoreSignals() {
	signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT,
		syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGPIPE)
}

// startReaper waits for every exited child on SIGCHLD so zombies never pile up under PID 1.
func startReaper() (stop func()) {
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGCHLD)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-sigs:
				for {
					var ws syscall.WaitStatus
					pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
					if pid <= 0 || err != nil {
						break
					}
				}
			}
		}
	}()
	return func() { signal.Stop(sigs); close(done) }
}
