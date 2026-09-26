package check

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/net/netcheck"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
)

type Observation uint8

const (
	ObservationUnknown Observation = iota
	ObservationAvailable
	ObservationUnavailable
)

type NATMapping uint8

const (
	NATMappingUnknown NATMapping = iota
	NATMappingStable
	NATMappingVariesByDestination
)

type NetworkFacts struct {
	CollectedAt time.Time

	UDP       Observation
	IPv4STUN  Observation
	IPv6STUN  Observation
	OSHasIPv6 Observation

	STUNProbeCompleted bool

	DERPTCP443 Observation

	FastestDERP        string
	FastestDERPName    string
	FastestDERPLatency time.Duration
	DERPLatencies      map[string]time.Duration

	DERPProbeCompleted bool

	NATMapping      NATMapping
	CollectionError string
}

type NetworkReport struct {
	Facts   NetworkFacts
	Results []Result
	Outcome Outcome
}

type NetworkFactsProvider interface {
	CollectNetworkFacts(context.Context) (NetworkFacts, error)
}

type networkAPIProvider struct {
	client *local.Client
}

func NewNetworkClient() NetworkFactsProvider {
	return networkAPIProvider{client: &local.Client{}}
}

func (p networkAPIProvider) CollectNetworkFacts(ctx context.Context) (NetworkFacts, error) {
	derpMap, err := p.client.CurrentDERPMap(ctx)
	if err != nil {
		return NetworkFacts{}, fmt.Errorf("fetch DERP map: %w", err)
	}
	if derpMap == nil {
		return NetworkFacts{}, errors.New("LocalAPI returned no DERP map")
	}

	netMon := netmon.NewStatic()
	defer netMon.Close()

	netcheckClient := &netcheck.Client{NetMon: netMon, Logf: func(string, ...any) {}}
	if err := netcheckClient.Standalone(ctx, ":0"); err != nil {
		return NetworkFacts{}, fmt.Errorf("start netcheck standalone probe: %w", err)
	}

	stunReport, stunErr := netcheckClient.GetReport(ctx, derpMap, &netcheck.GetReportOpts{OnlySTUN: true})
	derpReport, derpErr := netcheckClient.GetReport(ctx, derpMap, &netcheck.GetReportOpts{OnlyTCP443: true})
	facts := factsFromNetworkReports(derpMap, stunReport, stunErr, derpReport, derpErr)
	if stunErr != nil && derpErr != nil {
		return facts, fmt.Errorf("STUN probe: %v; DERP TCP/443 probe: %w", stunErr, derpErr)
	}
	if stunErr != nil {
		return facts, fmt.Errorf("STUN probe: %w", stunErr)
	}
	if derpErr != nil {
		return facts, fmt.Errorf("DERP TCP/443 probe: %w", derpErr)
	}
	return facts, nil
}

func factsFromNetworkReports(derpMap *tailcfg.DERPMap, stunReport *netcheck.Report, stunErr error, derpReport *netcheck.Report, derpErr error) NetworkFacts {
	facts := NetworkFacts{}
	if stunErr == nil && stunReport != nil {
		facts.STUNProbeCompleted = true
		facts.UDP = udpObservation(stunReport)
		facts.IPv4STUN = ipObservation(stunReport.IPv4, stunReport.IPv4CanSend)
		facts.IPv6STUN = ipObservation(stunReport.IPv6, stunReport.IPv6CanSend)
		facts.OSHasIPv6 = boolObservation(stunReport.OSHasIPv6)
		facts.NATMapping = natMappingFromReport(stunReport)
	}
	if derpErr == nil && derpReport != nil {
		facts.DERPProbeCompleted = true
		facts.DERPLatencies = make(map[string]time.Duration, len(derpReport.RegionLatency))
		fastestSelected := false
		for regionID, latency := range derpReport.RegionLatency {
			name := derpRegionName(derpMap, regionID)
			facts.DERPLatencies[name] = latency
			if !fastestSelected || latency < facts.FastestDERPLatency {
				fastestSelected = true
				facts.FastestDERP = ""
				facts.FastestDERPName = ""
				if derpMap != nil {
					if region := derpMap.Regions[regionID]; region != nil {
						facts.FastestDERP = region.RegionCode
						facts.FastestDERPName = region.RegionName
					}
				}
				facts.FastestDERPLatency = latency
			}
		}
		if len(derpReport.RegionLatency) > 0 {
			facts.DERPTCP443 = ObservationAvailable
		} else {
			facts.DERPTCP443 = ObservationUnavailable
		}
	}
	return facts
}

func udpObservation(report *netcheck.Report) Observation {
	if report.UDP {
		return ObservationAvailable
	}
	if report.IPv4CanSend || report.IPv6CanSend {
		return ObservationUnavailable
	}
	return ObservationUnknown
}

func ipObservation(observed, canSend bool) Observation {
	if observed {
		return ObservationAvailable
	}
	if canSend {
		return ObservationUnavailable
	}
	return ObservationUnknown
}

func boolObservation(value bool) Observation {
	if value {
		return ObservationAvailable
	}
	return ObservationUnavailable
}

func natMappingFromReport(report *netcheck.Report) NATMapping {
	value, ok := report.MappingVariesByDestIP.Get()
	if !ok {
		return NATMappingUnknown
	}
	if value {
		return NATMappingVariesByDestination
	}
	return NATMappingStable
}

func derpRegionName(derpMap *tailcfg.DERPMap, regionID int) string {
	if derpMap != nil {
		if region, ok := derpMap.Regions[regionID]; ok && region != nil {
			if region.RegionCode != "" {
				return region.RegionCode
			}
			if region.RegionName != "" {
				return region.RegionName
			}
		}
	}
	return strconv.Itoa(regionID)
}

func CollectNetwork(ctx context.Context, provider NetworkFactsProvider, now time.Time) NetworkReport {
	facts, err := provider.CollectNetworkFacts(ctx)
	facts.CollectedAt = now
	if err != nil {
		facts.CollectionError = err.Error()
	}
	return EvaluateNetwork(facts)
}

func EvaluateNetwork(facts NetworkFacts) NetworkReport {
	if facts.CollectionError != "" {
		return NetworkReport{
			Facts: facts,
			Results: []Result{{
				ID: "network_collection", Label: "Network probe", Severity: Unknown, Value: "incomplete",
				Explanation: facts.CollectionError,
			}},
			Outcome: OutcomeUnreliable,
		}
	}

	udp := networkUDPResult(facts)
	derp := networkDERPResult(facts)
	path := networkPathResult(facts)
	results := []Result{
		path,
		udp,
		derp,
		observationResult("ipv4_stun", "IPv4 STUN", facts.IPv4STUN),
		observationResult("ipv6_stun", "IPv6 STUN", facts.IPv6STUN),
		observationResult("os_ipv6", "OS IPv6", facts.OSHasIPv6),
		fastestDERPResult(facts),
		derpLatencyResult(facts),
		networkNATResult(facts),
	}
	return NetworkReport{Facts: facts, Results: results, Outcome: networkOutcome(facts)}
}

func networkOutcome(facts NetworkFacts) Outcome {
	if !facts.STUNProbeCompleted || !facts.DERPProbeCompleted || facts.UDP == ObservationUnknown || facts.DERPTCP443 == ObservationUnknown {
		return OutcomeUnreliable
	}
	if facts.UDP == ObservationUnavailable && facts.DERPTCP443 == ObservationUnavailable {
		return OutcomeDefiniteFail
	}
	return OutcomeUsable
}

func networkPathResult(facts NetworkFacts) Result {
	result := Result{ID: "network_path", Label: "Network path"}
	switch {
	case facts.UDP == ObservationAvailable && facts.DERPTCP443 == ObservationAvailable:
		result.Severity = Pass
		result.Value = "UDP and DERP TCP/443 available"
	case facts.UDP == ObservationUnavailable && facts.DERPTCP443 == ObservationAvailable:
		result.Severity = Warn
		result.Value = "UDP unavailable; DERP TCP/443 reachable"
		result.Explanation = "A UDP STUN round trip could not be established. Direct peer-to-peer connectivity may be limited."
	case facts.UDP == ObservationAvailable && facts.DERPTCP443 == ObservationUnavailable:
		result.Severity = Warn
		result.Value = "UDP available; DERP TCP/443 unavailable"
		result.Explanation = "Direct connections may still work, but no usable DERP fallback path was observed."
	case facts.UDP == ObservationUnavailable && facts.DERPTCP443 == ObservationUnavailable:
		result.Severity = Fail
		result.Value = "UDP and DERP TCP/443 unavailable"
		result.Explanation = "No usable Tailscale data path was observed."
	default:
		result.Severity = Unknown
		result.Value = "incomplete"
		result.Explanation = "The probe did not provide enough evidence to assess network readiness."
	}
	return result
}

func networkUDPResult(facts NetworkFacts) Result {
	result := Result{ID: "udp_connectivity", Label: "UDP connectivity"}
	switch facts.UDP {
	case ObservationAvailable:
		result.Severity, result.Value = Pass, "available"
	case ObservationUnavailable:
		result.Severity, result.Value = Warn, "unavailable"
	default:
		result.Severity, result.Value = Unknown, "unknown"
	}
	return result
}

func networkDERPResult(facts NetworkFacts) Result {
	result := Result{ID: "derp_tcp443", Label: "DERP TCP/443"}
	switch facts.DERPTCP443 {
	case ObservationAvailable:
		result.Severity, result.Value = Pass, "reachable"
	case ObservationUnavailable:
		result.Severity, result.Value = Warn, "unavailable"
	default:
		result.Severity, result.Value = Unknown, "unknown"
	}
	return result
}

func observationResult(id, label string, observation Observation) Result {
	return Result{ID: id, Label: label, Severity: Pass, Value: observationText(observation)}
}

func fastestDERPResult(facts NetworkFacts) Result {
	result := Result{ID: "fastest_derp", Label: "Fastest DERP", Severity: Pass}
	if facts.FastestDERP == "" && facts.FastestDERPName == "" {
		result.Severity = Unknown
		result.Value = "unavailable"
		return result
	}
	result.Value = facts.FastestDERP
	if facts.FastestDERPName != "" {
		result.Value = facts.FastestDERPName
		if facts.FastestDERP != "" {
			result.Value += " (" + facts.FastestDERP + ")"
		}
	}
	return result
}

func derpLatencyResult(facts NetworkFacts) Result {
	result := Result{ID: "derp_latency", Label: "TCP/443 latency", Severity: Pass}
	if facts.DERPTCP443 != ObservationAvailable {
		result.Severity = Unknown
		result.Value = "unknown"
		return result
	}
	result.Value = facts.FastestDERPLatency.Round(time.Millisecond).String()
	return result
}

func networkNATResult(facts NetworkFacts) Result {
	result := Result{ID: "nat_mapping", Label: "NAT mapping"}
	switch facts.NATMapping {
	case NATMappingStable:
		result.Severity, result.Value = Pass, "stable"
	case NATMappingVariesByDestination:
		result.Severity, result.Value = Warn, "varies by destination"
	default:
		result.Severity, result.Value = Unknown, "unknown"
	}
	return result
}

func observationText(observation Observation) string {
	switch observation {
	case ObservationAvailable:
		return "observed"
	case ObservationUnavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

func PresentNetwork(report NetworkReport) Presentation {
	presentation := Presentation{Summary: networkSummary(report.Outcome, report.Results)}
	if collection, ok := networkResultByID(report.Results, "network_collection"); ok {
		presentation.Primary = []Result{collection}
		return presentation
	}
	if path, ok := networkResultByID(report.Results, "network_path"); ok {
		if path.Severity != Pass {
			presentation.Primary = append(presentation.Primary, path)
		}
	}
	for _, id := range []string{"udp_connectivity", "derp_tcp443", "nat_mapping"} {
		if result, ok := networkResultByID(report.Results, id); ok {
			presentation.Supporting = append(presentation.Supporting, result)
		}
	}
	for _, id := range []string{"ipv4_stun", "ipv6_stun", "os_ipv6", "fastest_derp", "derp_latency"} {
		if result, ok := networkResultByID(report.Results, id); ok {
			presentation.Descriptive = append(presentation.Descriptive, result)
		}
	}
	return presentation
}

func RenderNetwork(w io.Writer, report NetworkReport) error {
	presentation := PresentNetwork(report)
	if _, err := fmt.Fprintf(w, "Summary: %s\n", presentation.Summary); err != nil {
		return err
	}
	writeNetworkGroup := func(title string, results []Result, showExplanation bool) error {
		if len(results) == 0 {
			return nil
		}
		if _, err := fmt.Fprintf(w, "\n%s:\n", title); err != nil {
			return err
		}
		for _, result := range results {
			if _, err := fmt.Fprintf(w, "  %-19s %s\n", result.Label, result.Value); err != nil {
				return err
			}
			if showExplanation && result.Explanation != "" {
				if _, err := fmt.Fprintf(w, "                      %s\n", result.Explanation); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := writeNetworkGroup("Primary finding", presentation.Primary, true); err != nil {
		return err
	}
	if err := writeNetworkGroup("Supporting evidence", presentation.Supporting, false); err != nil {
		return err
	}
	return writeNetworkGroup("Network information", presentation.Descriptive, false)
}

func networkSummary(outcome Outcome, results []Result) string {
	if outcome == OutcomeUsable {
		if path, ok := networkResultByID(results, "network_path"); ok {
			if path.Severity == Warn {
				if strings.Contains(path.Value, "UDP unavailable") {
					return "WARN  Direct connectivity may be limited"
				}
				return "WARN  Relay fallback is unavailable"
			}
		}
		return "PASS  Network readiness looks healthy"
	}
	if outcome == OutcomeDefiniteFail {
		return "FAIL  No usable Tailscale data path was observed"
	}
	return "UNKNOWN  Unable to establish reliable network readiness"
}

func networkResultByID(results []Result, id string) (Result, bool) {
	for _, result := range results {
		if result.ID == id {
			return result, true
		}
	}
	return Result{}, false
}
