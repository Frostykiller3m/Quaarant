package daemon

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	qtdv1 "github.com/Frostykiller3m/Quaarant/internal/api/qtd/v1"
	"github.com/Frostykiller3m/Quaarant/internal/backend"
	"github.com/Frostykiller3m/Quaarant/internal/events"
	"github.com/Frostykiller3m/Quaarant/internal/honeytoken"
	"github.com/Frostykiller3m/Quaarant/internal/netpol"
)

// netRecord is a sandbox's network, saved with its record so a restarted qtd can adopt
// the link (which outlives qtd) and keep policing it.
type netRecord struct {
	Mode  string   `json:"mode"` // "log" or "allow"
	Allow []string `json:"allow,omitempty"`
	Kind  int      `json:"kind"` // netpol.Kind
	Index int      `json:"index"`
}

func (n *netRecord) rules() netpol.Rules {
	r := netpol.Rules{Mode: netpol.ModeLog, Allow: n.Allow}
	if n.Mode == "allow" {
		r.Mode = netpol.ModeAllow
	}
	return r
}

// linkOwner is implemented by backends whose link a process other than qtd opens (the
// jailed VMM opens its tap as its own uid).
type linkOwner interface {
	LinkOwner(id string) int
}

// rulesFromProto validates a create request's policy; networked is false for --net=none.
func rulesFromProto(p *qtdv1.NetPolicy) (rules netpol.Rules, networked bool, err error) {
	switch p.GetMode() {
	case qtdv1.NetPolicy_MODE_UNSPECIFIED, qtdv1.NetPolicy_MODE_NONE:
		if len(p.GetAllowDomains()) > 0 {
			return netpol.Rules{}, false, fmt.Errorf("--net=none takes no domains")
		}
		return netpol.Rules{}, false, nil
	case qtdv1.NetPolicy_MODE_LOG:
		rules = netpol.Rules{Mode: netpol.ModeLog, Allow: p.GetAllowDomains()}
	case qtdv1.NetPolicy_MODE_ALLOW:
		if len(p.GetAllowDomains()) > netpol.MaxAllow {
			return netpol.Rules{}, false, fmt.Errorf("at most %d allowed domains", netpol.MaxAllow)
		}
		rules = netpol.Rules{Mode: netpol.ModeAllow, Allow: p.GetAllowDomains()}
	default:
		return netpol.Rules{}, false, fmt.Errorf("unknown network mode %v", p.GetMode())
	}
	rules, err = rules.Normalize()
	return rules, true, err
}

func netToProto(n *netRecord) *qtdv1.NetPolicy {
	switch {
	case n == nil:
		return &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_NONE}
	case n.Mode == "allow":
		return &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_ALLOW, AllowDomains: n.Allow}
	}
	return &qtdv1.NetPolicy{Mode: qtdv1.NetPolicy_MODE_LOG}
}

// netEmitter writes a sandbox's network events (host-observed) to its event log, while the
// sandbox exists.
func (s *Service) netEmitter(id string) netpol.Emitter {
	return func(p events.Payload) {
		if _, ok := s.reg.get(id); !ok {
			return // removed: its proxy is shutting down
		}
		_ = s.eventLogFor(id).Emit(context.Background(), events.SourceHost, p)
	}
}

// attach gives sandbox id its link (a netns for gvisor, a tap for vm).
func (s *Service) attach(ctx context.Context, id string, iso backend.Isolation, be backend.Backend, rules netpol.Rules) (*netpol.Link, *netRecord, error) {
	kind, owner := netpol.Netns, 0
	if iso == backend.IsolationVM {
		kind = netpol.Tap
		lo, ok := be.(linkOwner)
		if !ok {
			return nil, nil, status.Error(codes.FailedPrecondition, "the vm backend cannot take a network link")
		}
		owner = lo.LinkOwner(id)
	}
	l, err := s.opts.Net.Attach(ctx, id, kind, owner, rules, s.netEmitter(id))
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "network: %v", err)
	}
	nr := &netRecord{Mode: rules.Mode.String(), Allow: rules.Allow, Kind: int(kind), Index: l.Index}
	return l, nr, nil
}

func (s *Service) detach(ctx context.Context, id string) error {
	if s.opts.Net == nil {
		return nil
	}
	return s.opts.Net.Detach(ctx, id)
}

// adoptLinks takes over the links of sandboxes that survived a qtd restart, then removes
// links nothing owns.
func (s *Service) adoptLinks(ctx context.Context) {
	if s.opts.Net == nil {
		return
	}
	for _, rec := range s.reg.list() {
		if rec.Net == nil {
			continue
		}
		rules := rec.Net.rules()
		rules.Honey = honeytoken.NewMatcher(s.honeySet(rec.ID))
		if _, err := s.opts.Net.Adopt(rec.ID, netpol.Kind(rec.Net.Kind), rec.Net.Index, rules, s.netEmitter(rec.ID)); err != nil {
			s.log.Error("sandbox network not restored; its traffic is dropped", "id", rec.ID, "err", err)
		}
	}
	if err := s.opts.Net.Prune(ctx); err != nil {
		s.log.Warn("prune sandbox links", "err", err)
	}
}
