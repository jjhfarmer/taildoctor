package check

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/client/local"
	"tailscale.com/types/dnstype"
)

type LookupState string

const (
	LookupNotAttempted       LookupState = "not_attempted"
	LookupFailed             LookupState = "failed"
	LookupNoAddress          LookupState = "no_address"
	LookupResolvedExpected   LookupState = "resolved_expected"
	LookupResolvedUnexpected LookupState = "resolved_unexpected"
	LookupIncomplete         LookupState = "incomplete"
)

type LookupFact struct {
	State           LookupState
	ReturnedIPs     []string
	MatchedExpected bool
	// A and AAAA are populated only for the Tailscale DNS path.
	A, AAAA LookupState
}

type DNSFacts struct {
	CollectedAt time.Time

	AcceptsTailscaleDNS Observation
	MagicDNS            Observation
	MagicDNSSuffix      string
	SelfDNSName         string
	SelfTailscaleIPs    []string

	DNSConfigAvailable  bool
	GlobalResolverCount int
	SplitDNSRouteCount  int
	SearchDomainCount   int

	TailscaleLookup LookupFact
	OSLookup        LookupFact
}

type DNSReport struct {
	Facts   DNSFacts
	Results []Result
	Outcome Outcome
}

type DNSFactsProvider interface {
	CollectDNSFacts(context.Context) (DNSFacts, error)
}

type dnsAPIProvider struct {
	client   *local.Client
	resolver *net.Resolver
}

func NewDNSClient() DNSFactsProvider {
	return dnsAPIProvider{client: &local.Client{}, resolver: net.DefaultResolver}
}

func (p dnsAPIProvider) CollectDNSFacts(ctx context.Context) (DNSFacts, error) {
	f := DNSFacts{TailscaleLookup: LookupFact{State: LookupNotAttempted, A: LookupNotAttempted, AAAA: LookupNotAttempted}, OSLookup: LookupFact{State: LookupNotAttempted}}
	status, err := p.client.StatusWithoutPeers(ctx)
	if err != nil || status == nil {
		return f, errors.New("status unavailable")
	}
	if status.CurrentTailnet != nil {
		f.MagicDNS = dnsObservation(status.CurrentTailnet.MagicDNSEnabled)
		f.MagicDNSSuffix = status.CurrentTailnet.MagicDNSSuffix
	}
	if status.Self != nil {
		f.SelfDNSName = status.Self.DNSName
	}
	for _, ip := range status.TailscaleIPs {
		f.SelfTailscaleIPs = append(f.SelfTailscaleIPs, ip.String())
	}
	prefs, err := p.client.GetPrefs(ctx)
	if err != nil || prefs == nil {
		return f, errors.New("DNS preferences unavailable")
	}
	f.AcceptsTailscaleDNS = dnsObservation(prefs.CorpDNS)
	if config, err := p.client.DNSConfig(ctx); err == nil && config != nil {
		f.DNSConfigAvailable = true
		f.GlobalResolverCount = len(config.Resolvers)
		f.SplitDNSRouteCount = len(config.Routes)
		f.SearchDomainCount = len(config.Domains)
	}
	if f.MagicDNS != ObservationAvailable || f.SelfDNSName == "" || len(f.SelfTailscaleIPs) == 0 {
		return f, nil
	}
	// Neither path depends on the other path's result.
	f.TailscaleLookup = tailscaleSelfLookup(ctx, p.client.QueryDNS, f.SelfDNSName, f.SelfTailscaleIPs)
	f.OSLookup = osSelfLookup(ctx, p.resolver.LookupHost, f.SelfDNSName, f.SelfTailscaleIPs)
	return f, nil
}

func dnsObservation(v bool) Observation {
	if v {
		return ObservationAvailable
	}
	return ObservationUnavailable
}

type dnsQueryFunc func(context.Context, string, string) ([]byte, []*dnstype.Resolver, error)

func tailscaleSelfLookup(ctx context.Context, query dnsQueryFunc, name string, expected []string) LookupFact {
	f := LookupFact{State: LookupNotAttempted, A: LookupNotAttempted, AAAA: LookupNotAttempted}
	var has4, has6 bool
	for _, value := range expected {
		if ip, err := netip.ParseAddr(value); err == nil {
			has4 = has4 || ip.Is4()
			has6 = has6 || ip.Is6()
		}
	}
	for _, q := range []struct {
		enabled bool
		kind    string
		state   *LookupState
	}{{has4, "A", &f.A}, {has6, "AAAA", &f.AAAA}} {
		if !q.enabled {
			continue
		}
		packet, _, err := query(ctx, name, q.kind)
		if err != nil {
			*q.state = LookupIncomplete
			continue
		}
		addresses, state := parseSelfDNSResponse(packet, name, q.kind)
		if state == LookupResolvedUnexpected {
			state = classifyAddresses(addresses, expected).State
		}
		*q.state = state
		f.ReturnedIPs = append(f.ReturnedIPs, addresses...)
	}
	f.State = combineFamilyLookups(f.A, f.AAAA)
	f.MatchedExpected = f.State == LookupResolvedExpected
	return f
}

func combineFamilyLookups(states ...LookupState) LookupState {
	var unexpected, incomplete, attempted bool
	for _, state := range states {
		switch state {
		case LookupResolvedExpected:
			return LookupResolvedExpected
		case LookupResolvedUnexpected:
			unexpected, attempted = true, true
		case LookupIncomplete:
			incomplete, attempted = true, true
		case LookupFailed, LookupNoAddress:
			attempted = true
		}
	}
	if incomplete {
		return LookupIncomplete
	}
	if unexpected {
		return LookupResolvedUnexpected
	}
	if attempted {
		return LookupFailed
	}
	return LookupNotAttempted
}

func parseSelfDNSResponse(packet []byte, name, kind string) ([]string, LookupState) {
	var parser dnsmessage.Parser
	header, err := parser.Start(packet)
	if err != nil || !header.Response || header.Truncated {
		return nil, LookupIncomplete
	}
	question, err := parser.Question()
	if err != nil || !strings.EqualFold(question.Name.String(), name) ||
		(kind == "A" && question.Type != dnsmessage.TypeA) ||
		(kind == "AAAA" && question.Type != dnsmessage.TypeAAAA) || question.Class != dnsmessage.ClassINET {
		return nil, LookupIncomplete
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, LookupIncomplete
	}
	answers, err := parser.AllAnswers()
	if err != nil {
		return nil, LookupIncomplete
	}
	if err := parser.SkipAllAuthorities(); err != nil {
		return nil, LookupIncomplete
	}
	if err := parser.SkipAllAdditionals(); err != nil {
		return nil, LookupIncomplete
	}
	if header.RCode == dnsmessage.RCodeNameError {
		return nil, LookupFailed
	}
	if header.RCode != dnsmessage.RCodeSuccess {
		return nil, LookupIncomplete
	}
	var ips []string
	for _, answer := range answers {
		if !strings.EqualFold(answer.Header.Name.String(), name) {
			continue
		}
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			if kind == "A" {
				ips = append(ips, netip.AddrFrom4(body.A).String())
			}
		case *dnsmessage.AAAAResource:
			if kind == "AAAA" {
				ips = append(ips, netip.AddrFrom16(body.AAAA).String())
			}
		}
	}
	if len(ips) == 0 {
		return nil, LookupNoAddress
	}
	return ips, LookupResolvedUnexpected // caller compares with expected addresses
}

func classifyAddresses(addresses, expected []string) LookupFact {
	f := LookupFact{State: LookupResolvedUnexpected, ReturnedIPs: addresses}
	known := make(map[netip.Addr]bool, len(expected))
	for _, s := range expected {
		if ip, err := netip.ParseAddr(s); err == nil {
			known[ip.Unmap()] = true
		}
	}
	for _, s := range addresses {
		if ip, err := netip.ParseAddr(s); err == nil && known[ip.Unmap()] {
			f.State, f.MatchedExpected = LookupResolvedExpected, true
		}
	}
	return f
}

func osSelfLookup(ctx context.Context, lookup func(context.Context, string) ([]string, error), name string, expected []string) LookupFact {
	addresses, err := lookup(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound && !dnsErr.IsTemporary && !dnsErr.IsTimeout && ctx.Err() == nil {
			return LookupFact{State: LookupFailed}
		}
		return LookupFact{State: LookupIncomplete}
	}
	if len(addresses) == 0 {
		return LookupFact{State: LookupFailed}
	}
	f := classifyAddresses(addresses, expected)
	// Keep only parseable IP addresses; a malformed resolver result is inconclusive.
	f.ReturnedIPs = nil
	for _, s := range addresses {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return LookupFact{State: LookupIncomplete}
		}
		f.ReturnedIPs = append(f.ReturnedIPs, ip.String())
	}
	return f
}

func CollectDNS(ctx context.Context, provider DNSFactsProvider, now time.Time) DNSReport {
	f, err := provider.CollectDNSFacts(ctx)
	f.CollectedAt = now
	return EvaluateDNS(f, err)
}

func EvaluateDNS(f DNSFacts, collectionErr error) DNSReport {
	r := DNSReport{Facts: f}
	if collectionErr != nil || f.MagicDNS == ObservationUnknown || f.AcceptsTailscaleDNS == ObservationUnknown {
		r.Results = append(r.Results, Result{ID: "dns_evidence", Label: "DNS evidence", Severity: Unknown, Value: "incomplete", Explanation: "Required status or DNS preferences could not be established."})
		r.Outcome = OutcomeUnreliable
		return r
	}
	if f.MagicDNS == ObservationUnavailable {
		r.Results = append(r.Results, Result{ID: "magicdns", Label: "MagicDNS", Severity: Warn, Value: "disabled", Explanation: "MagicDNS is disabled for this tailnet; self-name lookups were not attempted."})
		r.Outcome = OutcomeUsable
	} else if f.SelfDNSName == "" || len(f.SelfTailscaleIPs) == 0 || !validExpectedIPs(f.SelfTailscaleIPs) {
		r.Results = append(r.Results, Result{ID: "dns_evidence", Label: "DNS evidence", Severity: Unknown, Value: "incomplete", Explanation: "The advertised self FQDN or expected Tailscale addresses are unavailable."})
		r.Outcome = OutcomeUnreliable
	} else {
		severity, outcome := dnsVerdict(f.TailscaleLookup.State, f.OSLookup.State)
		if f.TailscaleLookup.State == LookupResolvedExpected &&
			(f.TailscaleLookup.A == LookupResolvedUnexpected || f.TailscaleLookup.AAAA == LookupResolvedUnexpected) {
			severity, outcome = Warn, OutcomeUsable
		}
		r.Outcome = outcome
		finding := Result{ID: "self_resolution", Label: "Self name", Severity: severity, Value: dnsVerdictText(severity), Explanation: dnsVerdictExplanation(severity)}
		if severity == Warn && (f.TailscaleLookup.A == LookupResolvedUnexpected || f.TailscaleLookup.AAAA == LookupResolvedUnexpected) {
			finding.Value = "conflicting address returned"
			finding.Explanation = "A tested DNS family returned an address not assigned to this node. At least one lookup path also found an expected address; the cause of the discrepancy is unknown."
		}
		r.Results = append(r.Results, finding)
	}
	r.Results = append(r.Results,
		Result{ID: "tailscale_dns", Label: "Tailscale DNS", Severity: dnsPrefSeverity(f.AcceptsTailscaleDNS), Value: dnsEnabledText(f.AcceptsTailscaleDNS)},
		Result{ID: "magicdns_state", Label: "MagicDNS", Severity: Pass, Value: dnsEnabledText(f.MagicDNS)},
	)
	if f.MagicDNS != ObservationUnknown {
		r.Results = append(r.Results,
			Result{ID: "tailscale_lookup", Label: "Tailscale lookup", Severity: lookupSeverity(f.TailscaleLookup.State), Value: lookupText(f.TailscaleLookup.State)},
			Result{ID: "os_lookup", Label: "OS lookup", Severity: lookupSeverity(f.OSLookup.State), Value: lookupText(f.OSLookup.State)},
		)
		if f.MagicDNS == ObservationAvailable {
			for _, family := range []struct {
				id, label string
				state     LookupState
			}{{"lookup_a", "A query", f.TailscaleLookup.A}, {"lookup_aaaa", "AAAA query", f.TailscaleLookup.AAAA}} {
				if family.state != LookupNotAttempted && !(family.state == LookupNoAddress && f.TailscaleLookup.State == LookupResolvedExpected) {
					r.Results = append(r.Results, Result{ID: family.id, Label: family.label, Severity: lookupSeverity(family.state), Value: lookupText(family.state)})
				}
			}
		}
	}
	if f.SelfDNSName != "" {
		r.Results = append(r.Results, Result{ID: "self_name", Label: "Self FQDN", Value: f.SelfDNSName})
	}
	if f.MagicDNSSuffix != "" {
		r.Results = append(r.Results, Result{ID: "dns_suffix", Label: "Tailnet suffix", Value: f.MagicDNSSuffix})
	}
	if f.DNSConfigAvailable {
		for _, entry := range []struct {
			id, label string
			count     int
		}{{"global_resolvers", "Global resolvers", f.GlobalResolverCount}, {"split_routes", "Split DNS routes", f.SplitDNSRouteCount}, {"search_domains", "Search domains", f.SearchDomainCount}} {
			r.Results = append(r.Results, Result{ID: entry.id, Label: entry.label, Value: fmt.Sprintf("%d configured", entry.count)})
		}
	} else {
		r.Results = append(r.Results, Result{ID: "dns_config", Label: "DNS context", Value: "unavailable"})
	}
	return r
}

func validExpectedIPs(ips []string) bool {
	for _, s := range ips {
		if _, err := netip.ParseAddr(s); err == nil {
			return true
		}
	}
	return false
}

func dnsVerdict(ts, os LookupState) (Severity, Outcome) {
	if ts == LookupResolvedExpected && os == LookupResolvedExpected {
		return Pass, OutcomeUsable
	}
	if ts == LookupResolvedExpected || os == LookupResolvedExpected {
		return Warn, OutcomeUsable
	}
	if (ts == LookupFailed || ts == LookupResolvedUnexpected) && (os == LookupFailed || os == LookupResolvedUnexpected) {
		return Fail, OutcomeDefiniteFail
	}
	return Unknown, OutcomeUnreliable
}

func dnsPrefSeverity(v Observation) Severity {
	if v == ObservationUnavailable {
		return Warn
	}
	return Pass
}

func dnsEnabledText(v Observation) string {
	if v == ObservationAvailable {
		return "enabled"
	}
	return "disabled"
}

func lookupSeverity(s LookupState) Severity {
	switch s {
	case LookupResolvedExpected:
		return Pass
	case LookupIncomplete, LookupNotAttempted:
		return Unknown
	default:
		return Warn
	}
}

func lookupText(s LookupState) string {
	switch s {
	case LookupResolvedExpected:
		return "expected address found"
	case LookupNoAddress:
		return "no address returned"
	case LookupResolvedUnexpected:
		return "unexpected address returned"
	case LookupFailed:
		return "name not resolved"
	case LookupIncomplete:
		return "incomplete"
	default:
		return "not attempted"
	}
}

func dnsVerdictText(s Severity) string {
	switch s {
	case Pass:
		return "expected address found on both paths"
	case Warn:
		return "DNS paths differ or are incomplete"
	case Fail:
		return "expected address not found"
	default:
		return "incomplete"
	}
}

func dnsVerdictExplanation(s Severity) string {
	switch s {
	case Warn:
		return "At least one DNS path returned this node's address; the other did not establish the same result. The cause is unknown."
	case Fail:
		return "Neither completed DNS path returned a known Tailscale address for the advertised self FQDN. This does not identify the cause."
	case Unknown:
		return "The lookup paths did not establish enough evidence to assess this name reliably."
	default:
		return "The tested name resolved to this node's address through both DNS paths."
	}
}

func PresentDNS(r DNSReport) Presentation {
	p := Presentation{Summary: dnsSummary(r)}
	for _, result := range r.Results {
		switch result.ID {
		case "self_resolution", "dns_evidence", "magicdns":
			if result.Severity != Pass {
				p.Primary = append(p.Primary, result)
			}
		case "tailscale_dns", "magicdns_state", "tailscale_lookup", "os_lookup", "lookup_a", "lookup_aaaa":
			if result.ID != "lookup_a" && result.ID != "lookup_aaaa" || result.Severity != Pass {
				p.Supporting = append(p.Supporting, result)
			}
		default:
			p.Descriptive = append(p.Descriptive, result)
		}
	}
	return p
}

func dnsSummary(r DNSReport) string {
	if r.Outcome == OutcomeDefiniteFail {
		return "FAIL  The tested self name did not resolve to this node"
	}
	if r.Outcome == OutcomeUnreliable {
		return "UNKNOWN  Unable to establish reliable DNS readiness"
	}
	if r.Facts.MagicDNS == ObservationUnavailable {
		return "WARN  MagicDNS is disabled for this tailnet"
	}
	if r.Facts.AcceptsTailscaleDNS == ObservationUnavailable {
		return "WARN  This node does not accept Tailscale DNS settings"
	}
	if r.Facts.TailscaleLookup.A == LookupResolvedUnexpected || r.Facts.TailscaleLookup.AAAA == LookupResolvedUnexpected {
		if r.Facts.TailscaleLookup.State == LookupResolvedExpected {
			return "WARN  Self-name lookup returned a conflicting address"
		}
	}
	if result, ok := findResult(r.Results, "self_resolution"); ok && result.Severity == Warn {
		return "WARN  Self-name resolution differs between DNS paths"
	}
	return "PASS  This node's MagicDNS name resolves to its Tailscale address"
}

func RenderDNS(w io.Writer, r DNSReport) error {
	p := PresentDNS(r)
	if _, err := fmt.Fprintf(w, "Summary: %s\n", p.Summary); err != nil {
		return err
	}
	for _, group := range []struct {
		name    string
		results []Result
	}{{"Primary finding", p.Primary}, {"Supporting evidence", p.Supporting}, {"Descriptive information", p.Descriptive}} {
		if len(group.results) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "\n%s:\n", group.name); err != nil {
			return err
		}
		for _, result := range group.results {
			if _, err := fmt.Fprintf(w, "  %-19s %s\n", result.Label, result.Value); err != nil {
				return err
			}
			if group.name == "Primary finding" && result.Explanation != "" {
				if _, err := fmt.Fprintf(w, "                      %s\n", result.Explanation); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
