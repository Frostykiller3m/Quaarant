//go:build !linux

package agent

func startReaper() (stop func()) { return func() {} }

func ignoreSignals() {}
