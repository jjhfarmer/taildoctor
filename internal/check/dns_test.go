package check

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/types/dnstype"
)

const selfFQDN = "laptop.example.ts.net."

type fakeDNSProvider struct {
	facts DNSFacts
	err   error
}

func (p fakeDNSProvider) CollectDNSFacts(context.Context) (DNSFacts, error) { return p.facts, p.err }

func dnsFacts(ts, os LookupState) DNSFacts {
	return DNSFacts{
		MagicDNS: ObservationAvailable, AcceptsTailscaleDNS: ObservationAvailable,
		MagicDNSSuffix: "example.ts.net", SelfDNSName: selfFQDN,
		SelfTailscaleIPs:   []string{"100.64.0.1"},
		DNSConfigAvailable: true, TailscaleLookup: LookupFact{State: ts}, OSLookup: LookupFact{State: os},
	}
}

func TestDNSVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ts, os   LookupState
		severity Severity
		outcome  Outcome
	}{
		{"both IPv4 expected", LookupResolvedExpected, LookupResolvedExpected, Pass, OutcomeUsable},
		{"both IPv6 expected", LookupResolvedExpected, LookupResolvedExpected, Pass, OutcomeUsable},
		{"tailscale succeeds OS fails", LookupResolvedExpected, LookupFailed, Warn, OutcomeUsable},
		{"OS succeeds tailscale fails", LookupFailed, LookupResolvedExpected, Warn, OutcomeUsable},
		{"one succeeds other incomplete", LookupResolvedExpected, LookupIncomplete, Warn, OutcomeUsable},
		{"both negative", LookupFailed, LookupFailed, Fail, OutcomeDefiniteFail},
		{"one unexpected one expected", LookupResolvedUnexpected, LookupResolvedExpected, Warn, OutcomeUsable},
		{"both unexpected", LookupResolvedUnexpected, LookupResolvedUnexpected, Fail, OutcomeDefiniteFail},
		{"one unexpected one negative", LookupResolvedUnexpected, LookupFailed, Fail, OutcomeDefiniteFail},
		{"one unexpected one incomplete", LookupResolvedUnexpected, LookupIncomplete, Unknown, OutcomeUnreliable},
		{"one negative one incomplete", LookupFailed, LookupIncomplete, Unknown, OutcomeUnreliable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := dnsFacts(tc.ts, tc.os)
			if tc.name == "both IPv6 expected" {
				f.SelfTailscaleIPs = []string{"fd7a:115c:a1e0::1"}
			}
			r := EvaluateDNS(f, nil)
			if r.Outcome != tc.outcome {
				t.Fatalf("outcome %s, want %s", r.Outcome, tc.outcome)
			}
			finding, _ := findResult(r.Results, "self_resolution")
			if finding.Severity != tc.severity {
				t.Fatalf("severity %s, want %s", finding.Severity, tc.severity)
			}
		})
	}
}

func TestDNSMissingAndOptionalEvidence(t *testing.T) {
	for _, tc := range []struct {
		name     string
		change   func(*DNSFacts)
		err      error
		outcome  Outcome
		severity Severity
	}{
		{"disabled MagicDNS", func(f *DNSFacts) {
			f.MagicDNS = ObservationUnavailable
			f.TailscaleLookup.State = LookupNotAttempted
			f.OSLookup.State = LookupNotAttempted
		}, nil, OutcomeUsable, Warn},
		{"CorpDNS disabled", func(f *DNSFacts) { f.AcceptsTailscaleDNS = ObservationUnavailable }, nil, OutcomeUsable, Pass},
		{"missing self FQDN", func(f *DNSFacts) { f.SelfDNSName = "" }, nil, OutcomeUnreliable, Unknown},
		{"missing IPs", func(f *DNSFacts) { f.SelfTailscaleIPs = nil }, nil, OutcomeUnreliable, Unknown},
		{"missing tailnet", func(f *DNSFacts) { f.MagicDNS = ObservationUnknown }, nil, OutcomeUnreliable, Unknown},
		{"status collection failure", func(f *DNSFacts) {}, errors.New("sensitive local API error"), OutcomeUnreliable, Unknown},
		{"no DNSConfig PASS", func(f *DNSFacts) { f.DNSConfigAvailable = false }, nil, OutcomeUsable, Pass},
		{"no DNSConfig FAIL", func(f *DNSFacts) {
			f.DNSConfigAvailable = false
			f.TailscaleLookup.State = LookupFailed
			f.OSLookup.State = LookupFailed
		}, nil, OutcomeDefiniteFail, Fail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := dnsFacts(LookupResolvedExpected, LookupResolvedExpected)
			tc.change(&f)
			r := CollectDNS(context.Background(), fakeDNSProvider{facts: f, err: tc.err}, time.Unix(123, 0))
			if r.Facts.CollectedAt != time.Unix(123, 0) || r.Outcome != tc.outcome {
				t.Fatalf("report: %#v", r)
			}
			finding := r.Results[0]
			if finding.Severity != tc.severity {
				t.Fatalf("severity %s, want %s", finding.Severity, tc.severity)
			}
			var out bytes.Buffer
			if err := RenderDNS(&out, r); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "sensitive local API error") {
				t.Fatal("leaked raw error")
			}
			if !r.Facts.DNSConfigAvailable && strings.Contains(out.String(), "0 configured") {
				t.Fatal("missing config rendered as zero")
			}
		})
	}
}

func dnsPacket(t *testing.T, code dnsmessage.RCode, kind dnsmessage.Type, ip string) []byte {
	t.Helper()
	name := dnsmessage.MustNewName(selfFQDN)
	m := dnsmessage.Message{Header: dnsmessage.Header{Response: true, RCode: code}, Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}}}
	if ip != "" {
		address := netip.MustParseAddr(ip)
		if kind == dnsmessage.TypeA {
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: kind, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: address.As4()}}}
		} else {
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: kind, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AAAAResource{AAAA: address.As16()}}}
		}
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDNSPacketClassification(t *testing.T) {
	if ips, state := parseSelfDNSResponse(dnsPacket(t, dnsmessage.RCodeNameError, dnsmessage.TypeA, ""), selfFQDN, "A"); state != LookupFailed || len(ips) != 0 {
		t.Fatalf("NXDOMAIN = %v/%s", ips, state)
	}
	if _, state := parseSelfDNSResponse(dnsPacket(t, dnsmessage.RCodeSuccess, dnsmessage.TypeA, ""), selfFQDN, "A"); state != LookupNoAddress {
		t.Fatalf("empty answer = %s", state)
	}
	if _, state := parseSelfDNSResponse([]byte{1, 2, 3}, selfFQDN, "A"); state != LookupIncomplete {
		t.Fatalf("malformed = %s", state)
	}
}

func TestTailscaleDNSFamiliesAndAddressMatching(t *testing.T) {
	var queries []string
	query := func(_ context.Context, name, kind string) ([]byte, []*dnstype.Resolver, error) {
		if name != selfFQDN {
			t.Fatalf("queried %s", name)
		}
		queries = append(queries, kind)
		if kind == "AAAA" {
			return dnsPacket(t, dnsmessage.RCodeNameError, dnsmessage.TypeAAAA, ""), nil, nil
		}
		return dnsPacket(t, dnsmessage.RCodeSuccess, dnsmessage.TypeA, "100.64.0.1"), nil, nil
	}
	f := tailscaleSelfLookup(context.Background(), query, selfFQDN, []string{"100.64.0.1", "fd7a:115c:a1e0::1"})
	if f.State != LookupResolvedExpected || !f.MatchedExpected || f.AAAA != LookupFailed || f.A != LookupResolvedExpected || !reflect.DeepEqual(queries, []string{"A", "AAAA"}) {
		t.Fatalf("lookup: %#v queries %v", f, queries)
	}
	queries = nil
	f = tailscaleSelfLookup(context.Background(), query, selfFQDN, []string{"100.64.0.2"})
	if f.State != LookupResolvedUnexpected || f.MatchedExpected || !reflect.DeepEqual(queries, []string{"A"}) {
		t.Fatalf("mismatch: %#v queries %v", f, queries)
	}
	queries = nil
	query6 := func(_ context.Context, _, kind string) ([]byte, []*dnstype.Resolver, error) {
		queries = append(queries, kind)
		return dnsPacket(t, dnsmessage.RCodeSuccess, dnsmessage.TypeAAAA, "fd7a:115c:a1e0::1"), nil, nil
	}
	f = tailscaleSelfLookup(context.Background(), query6, selfFQDN, []string{"fd7a:115c:a1e0::1"})
	if f.State != LookupResolvedExpected || f.A != LookupNotAttempted || !reflect.DeepEqual(queries, []string{"AAAA"}) {
		t.Fatalf("IPv6: %#v %v", f, queries)
	}
}

func TestDNSDualStackEmptyAAAAIsHealthy(t *testing.T) {
	query := func(_ context.Context, name, kind string) ([]byte, []*dnstype.Resolver, error) {
		if name != selfFQDN {
			t.Fatalf("queried %s", name)
		}
		if kind == "A" {
			return dnsPacket(t, dnsmessage.RCodeSuccess, dnsmessage.TypeA, "100.64.0.1"), nil, nil
		}
		return dnsPacket(t, dnsmessage.RCodeSuccess, dnsmessage.TypeAAAA, ""), nil, nil
	}
	f := dnsFacts(LookupNotAttempted, LookupResolvedExpected)
	f.SelfTailscaleIPs = []string{"100.64.0.1", "fd7a:115c:a1e0::1"}
	f.TailscaleLookup = tailscaleSelfLookup(context.Background(), query, f.SelfDNSName, f.SelfTailscaleIPs)
	if f.TailscaleLookup.A != LookupResolvedExpected || f.TailscaleLookup.AAAA != LookupNoAddress || f.TailscaleLookup.State != LookupResolvedExpected {
		t.Fatalf("dual-stack lookup: %#v", f.TailscaleLookup)
	}
	r := EvaluateDNS(f, nil)
	if r.Outcome != OutcomeUsable || r.Results[0].Severity != Pass {
		t.Fatalf("expected PASS: %#v", r)
	}
	var output bytes.Buffer
	if err := RenderDNS(&output, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Summary: PASS") || strings.Contains(output.String(), "AAAA query") {
		t.Fatalf("benign empty AAAA should not appear as failure: %s", output.String())
	}
}

func TestDNSDualStackUnexpectedAAAAWarns(t *testing.T) {
	query := func(_ context.Context, _ string, kind string) ([]byte, []*dnstype.Resolver, error) {
		if kind == "A" {
			return dnsPacket(t, dnsmessage.RCodeSuccess, dnsmessage.TypeA, "100.64.0.1"), nil, nil
		}
		return dnsPacket(t, dnsmessage.RCodeSuccess, dnsmessage.TypeAAAA, "fd7a:115c:a1e0::99"), nil, nil
	}
	f := dnsFacts(LookupNotAttempted, LookupResolvedExpected)
	f.SelfTailscaleIPs = []string{"100.64.0.1", "fd7a:115c:a1e0::1"}
	f.TailscaleLookup = tailscaleSelfLookup(context.Background(), query, f.SelfDNSName, f.SelfTailscaleIPs)
	if f.TailscaleLookup.State != LookupResolvedExpected || f.TailscaleLookup.AAAA != LookupResolvedUnexpected {
		t.Fatalf("unexpected-family evidence lost: %#v", f.TailscaleLookup)
	}
	r := EvaluateDNS(f, nil)
	if r.Outcome != OutcomeUsable || r.Results[0].Severity != Warn {
		t.Fatalf("expected WARN with usable outcome: %#v", r)
	}
	var output bytes.Buffer
	if err := RenderDNS(&output, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Summary: WARN  Self-name lookup returned a conflicting address") || !strings.Contains(output.String(), "AAAA query") {
		t.Fatalf("conflicting AAAA should be visible: %s", output.String())
	}
}

func TestDNSNoFamilyMatchesFails(t *testing.T) {
	query := func(_ context.Context, _ string, kind string) ([]byte, []*dnstype.Resolver, error) {
		if kind == "A" {
			return dnsPacket(t, dnsmessage.RCodeSuccess, dnsmessage.TypeA, ""), nil, nil
		}
		return dnsPacket(t, dnsmessage.RCodeNameError, dnsmessage.TypeAAAA, ""), nil, nil
	}
	f := dnsFacts(LookupNotAttempted, LookupFailed)
	f.SelfTailscaleIPs = []string{"100.64.0.1", "fd7a:115c:a1e0::1"}
	f.TailscaleLookup = tailscaleSelfLookup(context.Background(), query, f.SelfDNSName, f.SelfTailscaleIPs)
	if f.TailscaleLookup.A != LookupNoAddress || f.TailscaleLookup.AAAA != LookupFailed || f.TailscaleLookup.State != LookupFailed {
		t.Fatalf("negative family facts: %#v", f.TailscaleLookup)
	}
	if r := EvaluateDNS(f, nil); r.Outcome != OutcomeDefiniteFail || r.Results[0].Severity != Fail {
		t.Fatalf("expected failure: %#v", r)
	}
}

func TestOSLookupClassification(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []string
		err       error
		want      LookupState
	}{
		{"IPv4 expected", []string{"100.64.0.1"}, nil, LookupResolvedExpected},
		{"IPv6 expected", []string{"fd7a:115c:a1e0::1"}, nil, LookupResolvedExpected},
		{"unexpected", []string{"203.0.113.9"}, nil, LookupResolvedUnexpected},
		{"not found", nil, &net.DNSError{IsNotFound: true}, LookupFailed},
		{"temporary not found", nil, &net.DNSError{IsNotFound: true, IsTemporary: true}, LookupIncomplete},
		{"timeout", nil, &net.DNSError{IsTimeout: true}, LookupIncomplete},
		{"arbitrary error", nil, errors.New("transport"), LookupIncomplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := osSelfLookup(context.Background(), func(_ context.Context, name string) ([]string, error) {
				if name != selfFQDN {
					t.Fatal(name)
				}
				return tc.addresses, tc.err
			}, selfFQDN, []string{"100.64.0.1", "fd7a:115c:a1e0::1"})
			if f.State != tc.want || f.MatchedExpected != (tc.want == LookupResolvedExpected) {
				t.Fatalf("fact: %#v", f)
			}
		})
	}
}

func TestRenderDNSMatrix(t *testing.T) {
	for _, tc := range []struct {
		ts, os  LookupState
		summary string
	}{
		{LookupResolvedExpected, LookupResolvedExpected, "Summary: PASS"},
		{LookupResolvedExpected, LookupIncomplete, "Summary: WARN"},
		{LookupFailed, LookupFailed, "Summary: FAIL"},
		{LookupFailed, LookupIncomplete, "Summary: UNKNOWN"},
	} {
		f := dnsFacts(tc.ts, tc.os)
		f.GlobalResolverCount = 2
		f.SplitDNSRouteCount = 3
		f.SearchDomainCount = 1
		var out bytes.Buffer
		if err := RenderDNS(&out, EvaluateDNS(f, nil)); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), tc.summary) || !strings.Contains(out.String(), "2 configured") || !strings.Contains(out.String(), "3 configured") {
			t.Fatalf("output: %s", out.String())
		}
		if strings.Contains(out.String(), "100.64.0.1") {
			t.Fatal("rendered address")
		}
	}
}
