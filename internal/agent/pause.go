// Package agent is the code of qt-agent, which runs inside sandboxes. It may only use the
// standard library and internal packages (checked by `make agent-deps`).
package agent

// Pause is the sandbox init for the gvisor backend: it reaps orphaned children (as PID 1 must)
// and never exits on its own. Signals sent from inside the sandbox are ignored, so sandboxed
// code cannot stop the sandbox (and its observation) with `kill 1`; qtd stops it from the host
// with SIGKILL (`runsc delete --force`). User commands arrive with `runsc exec`.
func Pause() int {
	ignoreSignals()
	stop := startReaper()
	defer stop()
	select {}
}
