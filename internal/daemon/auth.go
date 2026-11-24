package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// Peer is who is on the other end of the unix socket, from SO_PEERCRED (kernel-provided, so a
// client cannot lie about it).
type Peer struct {
	UID, GID uint32
	PID      int32
}

// PeerAuth is the gRPC AuthInfo for an authenticated unix-socket peer.
type PeerAuth struct {
	credentials.CommonAuthInfo
	Peer Peer
}

// AuthType implements credentials.AuthInfo.
func (PeerAuth) AuthType() string { return "peercred" }

// PeerFromContext returns the caller of an RPC.
func PeerFromContext(ctx context.Context) (Peer, bool) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return Peer{}, false
	}
	a, ok := p.AuthInfo.(PeerAuth)
	return a.Peer, ok
}

// Authorizer decides whether a peer may use qtd.
type Authorizer func(Peer) error

// ErrForbidden is returned for peers that are neither root nor allowed by group.
var ErrForbidden = errors.New("permission denied")

// peerCreds is gRPC transport credentials that authenticate unix-socket peers with
// SO_PEERCRED and reject unauthorized ones during the handshake (before any RPC is read).
type peerCreds struct {
	authorize Authorizer
	getPeer   func(net.Conn) (Peer, error)
}

// PeerCredentials returns transport credentials that admit only peers authorize accepts.
func PeerCredentials(authorize Authorizer) credentials.TransportCredentials {
	return &peerCreds{authorize: authorize, getPeer: peerOf}
}

func (c *peerCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	p, err := c.getPeer(conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("peer credentials: %w", err)
	}
	if err := c.authorize(p); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("uid %d gid %d pid %d: %w", p.UID, p.GID, p.PID, err)
	}
	return conn, PeerAuth{CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity}, Peer: p}, nil
}

func (*peerCreds) ClientHandshake(context.Context, string, net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, errors.New("peercred: server-side only")
}

func (*peerCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "peercred"}
}

func (c *peerCreds) Clone() credentials.TransportCredentials { cp := *c; return &cp }

func (*peerCreds) OverrideServerName(string) error { return nil }

// GroupAuthorizer admits root, the daemon's own uid, and members of gid (primary or
// supplementary group of the peer process).
func GroupAuthorizer(gid uint32, haveGroup bool, selfUID uint32) Authorizer {
	return func(p Peer) error {
		if p.UID == 0 || p.UID == selfUID {
			return nil
		}
		if haveGroup {
			if p.GID == gid {
				return nil
			}
			if groups, err := processGroups(p.PID); err == nil {
				for _, g := range groups {
					if g == gid {
						return nil
					}
				}
			}
		}
		return ErrForbidden
	}
}
