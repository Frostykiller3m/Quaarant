//go:build windows

package cli

import (
	"context"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
)

// forwardSignals is a no-op on Windows (qt talks to a Linux qtd; M7 adds --host).
func forwardSignals(context.Context, execIO, func(*qtdv1.ExecRequest) error) (stop func()) {
	return func() {}
}
