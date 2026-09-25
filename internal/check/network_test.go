package check

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"tailscale.com/net/netcheck"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
)

type fakeNetworkProvider struct {
	facts NetworkFacts
	err   error
}

func (f fakeNetworkProvider) CollectNetworkFacts(context.Context) (NetworkFacts, error) {
	return f.facts, f.err
}

func networkFactsFor(udp, derp Observation) NetworkFacts {
	return NetworkFacts{
		UDP:                udp,
		IPv4STUN:           ObservationAvailable,
		STUNProbeCompleted: true,
		DERPTCP443:         derp,
		DERPProbeCompleted: true,
		FastestDERP:        "lon",
		FastestDERPLatency: 18 * time.Millisecond,
		DERPLatencies:      map[string]time.Duration{"lon": 18 * time.Millisecond},
		NATMapping:         NATMappingStable,
	}
}

func TestEvaluateNetworkPathMatrix(t *testing.T) {
	tests := []struct {
		name     string
		udp      Observation
		derp     Observation
		severity Severity
		outcome  Outcome
	}{
		{"both available", ObservationAvailable, ObservationAvailable, Pass, OutcomeUsable},
		{"udp unavailable", ObservationUnavailable, ObservationAvailable, Warn, OutcomeUsable},
		{"derp unavailable", ObservationAvailable, ObservationUnavailable, Warn, OutcomeUsable},
		{"both unavailable", ObservationUnavailable, ObservationUnavailable, Fail, OutcomeDefiniteFail},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := EvaluateNetwork(networkFactsFor(test.udp, test.derp))
			result, ok := networkResultByID(report.Results, "network_path")
			if !ok {
				t.Fatal("network_path result missing")
			}
			if result.Severity != test.severity {
				t.Fatalf("severity = %q, want %q", result.Severity, test.severity)
			}
			if report.Outcome != test.outcome {
				t.Fatalf("outcome = %q, want %q", report.Outcome, test.outcome)
			}
		})
	}
}

func TestEvaluateNetworkUnknownObservation(t *testing.T) {
	facts := networkFactsFor(ObservationUnknown, ObservationAvailable)
	report := EvaluateNetwork(facts)
	if report.Outcome != OutcomeUnreliable {
		t.Fatalf("outcome = %q, want %q", report.Outcome, OutcomeUnreliable)
	}
}

func TestNetworkReportMappingAndFastestDERP(t *testing.T) {
	derpMap := &tailcfg.DERPMap{Regions: map[int]*tailcfg.DERPRegion{
		1: {RegionID: 1, RegionCode: "lon"},
		2: {RegionID: 2, RegionCode: "ams"},
	}}
	stun := &netcheck.Report{
		UDP:                   true,
		IPv4:                  true,
		IPv4CanSend:           true,
		IPv6CanSend:           true,
		OSHasIPv6:             true,
		MappingVariesByDestIP: opt.Bool("false"),
	}
	derp := &netcheck.Report{RegionLatency: map[int]time.Duration{
		1: 18 * time.Millisecond,
		2: 9 * time.Millisecond,
	}}
	facts := factsFromNetworkReports(derpMap, stun, nil, derp, nil)
	if facts.FastestDERP != "ams" || facts.FastestDERPLatency != 9*time.Millisecond {
		t.Fatalf("fastest DERP = %q/%v", facts.FastestDERP, facts.FastestDERPLatency)
	}
	if facts.NATMapping != NATMappingStable {
		t.Fatalf("NAT mapping = %d, want stable", facts.NATMapping)
	}
	if facts.UDP != ObservationAvailable || facts.IPv4STUN != ObservationAvailable || facts.IPv6STUN != ObservationUnavailable {
		t.Fatalf("unexpected STUN observations: %#v", facts)
	}
}

func TestNetworkReportPreservesSTUNWhenDERPProbeFails(t *testing.T) {
	stun := &netcheck.Report{UDP: true, IPv4: true, IPv4CanSend: true}
	facts := factsFromNetworkReports(nil, stun, nil, nil, errors.New("tcp probe failed"))
	if !facts.STUNProbeCompleted || facts.UDP != ObservationAvailable {
		t.Fatalf("STUN facts were not preserved: %#v", facts)
	}
	if facts.DERPProbeCompleted || facts.DERPTCP443 != ObservationUnknown {
		t.Fatalf("DERP facts were not left incomplete: %#v", facts)
	}
}

func TestNetworkReportPreservesDERPWhenSTUNProbeFails(t *testing.T) {
	derp := &netcheck.Report{RegionLatency: map[int]time.Duration{1: 20 * time.Millisecond}}
	facts := factsFromNetworkReports(nil, nil, errors.New("stun probe failed"), derp, nil)
	if facts.STUNProbeCompleted || facts.UDP != ObservationUnknown {
		t.Fatalf("STUN facts were not left incomplete: %#v", facts)
	}
	if !facts.DERPProbeCompleted || facts.DERPTCP443 != ObservationAvailable {
		t.Fatalf("DERP facts were not preserved: %#v", facts)
	}
}

func TestNetworkReportNATMappingStates(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		want  NATMapping
	}{
		{"unset", "", NATMappingUnknown},
		{"stable", "false", NATMappingStable},
		{"varies", "true", NATMappingVariesByDestination},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := &netcheck.Report{MappingVariesByDestIP: opt.Bool(test.value)}
			if got := natMappingFromReport(report); got != test.want {
				t.Fatalf("mapping = %d, want %d", got, test.want)
			}
		})
	}
}

func TestCollectNetworkPartialProbeFailures(t *testing.T) {
	stunFacts := networkFactsFor(ObservationAvailable, ObservationUnknown)
	report := CollectNetwork(context.Background(), fakeNetworkProvider{facts: stunFacts, err: errors.New("DERP TCP/443 probe failed")}, time.Unix(10, 0))
	if report.Outcome != OutcomeUnreliable {
		t.Fatalf("outcome = %q, want %q", report.Outcome, OutcomeUnreliable)
	}
}

func TestCollectNetworkStandaloneFailure(t *testing.T) {
	report := CollectNetwork(context.Background(), fakeNetworkProvider{err: errors.New("start netcheck standalone probe: bind failed")}, time.Unix(10, 0))
	if report.Facts.STUNProbeCompleted || report.Facts.DERPProbeCompleted {
		t.Fatal("setup failure fabricated completed probe facts")
	}
	if report.Outcome != OutcomeUnreliable {
		t.Fatalf("outcome = %q, want %q", report.Outcome, OutcomeUnreliable)
	}
}

func TestRenderNetworkOutcomes(t *testing.T) {
	tests := []struct {
		name  string
		facts NetworkFacts
		want  string
	}{
		{"pass", networkFactsFor(ObservationAvailable, ObservationAvailable), "Summary: PASS  Network readiness looks healthy"},
		{"udp warning", networkFactsFor(ObservationUnavailable, ObservationAvailable), "Summary: WARN  Direct connectivity may be limited"},
		{"derp warning", networkFactsFor(ObservationAvailable, ObservationUnavailable), "Summary: WARN  Relay fallback is unavailable"},
		{"failure", networkFactsFor(ObservationUnavailable, ObservationUnavailable), "Summary: FAIL  No usable Tailscale data path was observed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			if err := RenderNetwork(&output, EvaluateNetwork(test.facts)); err != nil {
				t.Fatalf("RenderNetwork returned error: %v", err)
			}
			if !strings.Contains(output.String(), test.want) {
				t.Fatalf("output missing %q:\n%s", test.want, output.String())
			}
		})
	}
}
