//go:build !linux

package daemon

import (
	"errors"
	"net"
)

// qtd only runs on Linux; elsewhere every peer is rejected.

func peerOf(net.Conn) (Peer, error)         { return Peer{}, errors.New("peer credentials need Linux") }
func processGroups(int32) ([]uint32, error) { return nil, errors.New("needs Linux") }
