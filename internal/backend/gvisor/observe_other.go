//go:build !linux

package gvisor

import (
	"log/slog"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

type observer struct{ traceConfig string }

func startObserver(backend.Spec, *slog.Logger) (*observer, error) { return nil, errLinuxOnly }
func (*observer) ready() error                                    { return errLinuxOnly }
func (*observer) stop()                                           {}
func (*observer) suppress(string) func()                          { return func() {} }
func (*observer) launched(int, *specs.Process)                    {}
