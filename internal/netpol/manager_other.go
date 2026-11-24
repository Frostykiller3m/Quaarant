//go:build !linux

package netpol

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/Frostykiller3m/Quaarant/internal/backend"
)

// Kind is the type of link a sandbox gets.
type Kind int

// Link kinds.
const (
	Netns Kind = iota + 1
	Tap
)

// Manager is Linux-only.
type Manager struct{}

// Link is one sandbox's attachment.
type Link struct {
	Sandbox string
	Kind    Kind
	Index   int
	Iface   string
	Netns   string
	Gateway netip.Addr
	Guest   netip.Prefix
	Rules   Rules
}

var errLinux = fmt.Errorf("netpol: sandbox networking needs Linux: %w", errors.ErrUnsupported)

// New is Linux-only.
func New(context.Context, Config) (*Manager, error) { return nil, errLinux }

// Network is what the backend needs to attach the sandbox.
func (*Link) Network() backend.Network { return backend.Network{} }

// Attach is Linux-only.
func (*Manager) Attach(context.Context, string, Kind, int, Rules, Emitter) (*Link, error) {
	return nil, errLinux
}

// Adopt is Linux-only.
func (*Manager) Adopt(string, Kind, int, Rules, Emitter) (*Link, error) { return nil, errLinux }

// Prune is Linux-only.
func (*Manager) Prune(context.Context) error { return nil }

// Release is Linux-only.
func (*Manager) Release() {}

// Detach is Linux-only.
func (*Manager) Detach(context.Context, string) error { return nil }

// Close is Linux-only.
func (*Manager) Close(context.Context) error { return nil }

// CreateTap is Linux-only.
func CreateTap(string, int) error { return errLinux }

// DeleteTap is Linux-only.
func DeleteTap(string) error { return errLinux }
