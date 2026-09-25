package check

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"tailscale.com/client/local"
	"tailscale.com/ipn/ipnstate"
)

type StatusProvider interface {
	CollectFacts(context.Context) (Facts, error)
}

type Facts struct {
	CollectedAt       time.Time
	DaemonVersion     string
	BackendState      string
	HaveNodeKey       bool
	AuthURLPresent    bool
	Identity          string
	TailscaleIPs      []string
	HealthWarnings    []string
	CurrentTailnet    string
	MagicDNSEnabled   bool
	CurrentTailnetSet bool
}

type Outcome string

const (
	OutcomeUsable       Outcome = "usable"
	OutcomeDefiniteFail Outcome = "definite_failure"
	OutcomeUnreliable   Outcome = "unable_to_establish_readiness"
)

type Severity string

const (
	Pass    Severity = "PASS"
	Warn    Severity = "WARN"
	Fail    Severity = "FAIL"
	Unknown Severity = "UNKNOWN"
)

type Result struct {
	ID             string
	Label          string
	Severity       Severity
	Value          string
	Explanation    string
	Recommendation string
}

type Report struct {
	Facts   Facts
	Results []Result
	Outcome Outcome
}

type Presentation struct {
	Summary     string
	Primary     []Result
	Supporting  []Result
	Descriptive []Result
}

func Present(report Report) Presentation {
	presentation := Presentation{}
	if result, ok := findResult(report.Results, "local_api"); ok && result.Severity == Fail {
		presentation.Primary = []Result{result}
		presentation.Summary = summaryFor(report.Outcome, presentation.Primary)
		return presentation
	}

	backend, _ := findResult(report.Results, "backend_state")
	authentication, _ := findResult(report.Results, "authentication")
	if backend.Severity == Fail || backend.Severity == Unknown {
		presentation.Primary = append(presentation.Primary, backend)
		presentation.Supporting = append(presentation.Supporting, authentication)
	} else if authentication.Severity == Fail || authentication.Severity == Unknown {
		presentation.Primary = append(presentation.Primary, authentication)
		presentation.Supporting = append(presentation.Supporting, backend)
	} else {
		presentation.Supporting = append(presentation.Supporting, backend, authentication)
	}

	if health, ok := findResult(report.Results, "health"); ok {
		presentation.Supporting = append(presentation.Supporting, health)
	}
	if identity, ok := findResult(report.Results, "node_identity"); ok {
		presentation.Descriptive = append(presentation.Descriptive, identity)
	}
	presentation.Summary = summaryFor(report.Outcome, presentation.Primary)
	return presentation
}

func Render(w io.Writer, report Report) error {
	presentation := Present(report)
	if _, err := fmt.Fprintf(w, "Summary: %s\n", presentation.Summary); err != nil {
		return err
	}
	writeGroup := func(title string, results []Result, descriptive bool) error {
		if len(results) == 0 {
			return nil
		}
		if _, err := fmt.Fprintf(w, "\n%s:\n", title); err != nil {
			return err
		}
		for _, result := range results {
			value := result.Value
			if !descriptive && result.ID == "health" && result.Explanation != "" {
				value = result.Explanation
			}
			if _, err := fmt.Fprintf(w, "  %-17s %s\n", result.Label, value); err != nil {
				return err
			}
			if !descriptive && title == "Primary finding" && result.Explanation != "" {
				if _, err := fmt.Fprintf(w, "                    %s\n", result.Explanation); err != nil {
					return err
				}
			}
			if !descriptive && title == "Primary finding" && result.Recommendation != "" {
				if _, err := fmt.Fprintf(w, "                    Recommendation: %s\n", result.Recommendation); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := writeGroup("Primary finding", presentation.Primary, false); err != nil {
		return err
	}
	if err := writeGroup("Supporting evidence", presentation.Supporting, false); err != nil {
		return err
	}
	return writeGroup("Descriptive information", presentation.Descriptive, true)
}

func summaryFor(outcome Outcome, primary []Result) string {
	switch outcome {
	case OutcomeUsable:
		return "PASS  Tailscale is ready"
	case OutcomeDefiniteFail:
		for _, result := range primary {
			if result.ID != "backend_state" {
				continue
			}
			switch result.Value {
			case "NeedsLogin":
				return "FAIL  Authentication required"
			case "NeedsMachineAuth":
				return "FAIL  Machine authorization required"
			}
		}
		return "FAIL  Tailscale is not ready"
	default:
		return "UNKNOWN  Unable to establish reliable readiness"
	}
}

func findResult(results []Result, id string) (Result, bool) {
	for _, result := range results {
		if result.ID == id {
			return result, true
		}
	}
	return Result{}, false
}

func Collect(ctx context.Context, provider StatusProvider, now time.Time) (Report, error) {
	facts, err := provider.CollectFacts(ctx)
	if err != nil {
		return Report{
			Facts: facts,
			Results: []Result{{
				ID: "local_api", Label: "LocalAPI", Severity: Fail, Value: "unavailable",
				Explanation: fmt.Sprintf("Unable to retrieve status from the LocalAPI: %v", err),
			}},
			Outcome: OutcomeUnreliable,
		}, nil
	}
	facts.CollectedAt = now
	return Evaluate(facts), nil
}

type localAPIProvider struct {
	client *local.Client
}

func NewClient() StatusProvider {
	return localAPIProvider{client: &local.Client{}}
}

func (p localAPIProvider) CollectFacts(ctx context.Context) (Facts, error) {
	status, err := p.client.StatusWithoutPeers(ctx)
	if err != nil {
		return Facts{}, fmt.Errorf("query LocalAPI status: %w", err)
	}
	if status == nil {
		return Facts{}, errors.New("LocalAPI returned no status")
	}
	return factsFromStatus(status), nil
}

func factsFromStatus(status *ipnstate.Status) Facts {
	facts := Facts{}

	facts.DaemonVersion = status.Version
	facts.BackendState = status.BackendState
	facts.HaveNodeKey = status.HaveNodeKey
	facts.AuthURLPresent = status.AuthURL != ""
	facts.HealthWarnings = append([]string(nil), status.Health...)
	facts.TailscaleIPs = make([]string, 0, len(status.TailscaleIPs))
	for _, ip := range status.TailscaleIPs {
		facts.TailscaleIPs = append(facts.TailscaleIPs, ip.String())
	}
	if status.Self != nil {
		facts.Identity = strings.TrimSuffix(status.Self.DNSName, ".")
		if facts.Identity == "" {
			facts.Identity = status.Self.HostName
		}
	}
	if status.CurrentTailnet != nil {
		facts.CurrentTailnetSet = true
		facts.CurrentTailnet = status.CurrentTailnet.Name
		facts.MagicDNSEnabled = status.CurrentTailnet.MagicDNSEnabled
	}

	return facts
}

func Evaluate(facts Facts) Report {
	results := []Result{
		{ID: "local_api", Label: "LocalAPI", Severity: Pass, Value: "reachable"},
		backendResult(facts.BackendState),
		authenticationResult(facts),
		nodeIdentityResult(facts),
		healthResult(facts.HealthWarnings),
	}
	return Report{Facts: facts, Results: results, Outcome: outcomeFor(results)}
}

func outcomeFor(results []Result) Outcome {
	for _, result := range results {
		if result.Severity == Fail {
			return OutcomeDefiniteFail
		}
	}
	for _, result := range results {
		if result.Severity == Unknown {
			return OutcomeUnreliable
		}
	}
	return OutcomeUsable
}

func backendResult(state string) Result {
	result := Result{ID: "backend_state", Label: "Backend state", Value: state}
	switch state {
	case "Running":
		result.Severity = Pass
	case "NeedsLogin":
		result.Severity = Fail
		result.Explanation = "The Tailscale node is not authenticated."
		result.Recommendation = "Sign in with Tailscale before retrying."
	case "NeedsMachineAuth":
		result.Severity = Fail
		result.Explanation = "The node is waiting for machine authorization."
	case "Starting":
		result.Severity = Warn
		result.Explanation = "The Tailscale backend is still starting."
	case "Stopped", "NoState":
		result.Severity = Fail
		result.Explanation = "The Tailscale backend is not operating."
	default:
		result.Severity = Unknown
		result.Explanation = "The backend state is not recognized by this version of Taildoctor."
	}
	return result
}

func authenticationResult(facts Facts) Result {
	result := Result{ID: "authentication", Label: "Authentication"}
	if facts.BackendState == "NeedsLogin" || facts.BackendState == "NeedsMachineAuth" || facts.AuthURLPresent {
		result.Severity = Fail
		result.Value = "action required"
		result.Explanation = "The node needs authentication or machine authorization before it can operate."
		return result
	}
	if facts.BackendState == "Running" && facts.HaveNodeKey && facts.CurrentTailnetSet && facts.Identity != "" {
		result.Severity = Pass
		result.Value = "authenticated"
		return result
	}
	result.Severity = Unknown
	result.Value = "incomplete"
	result.Explanation = "The available status does not prove that authentication is complete."
	return result
}

func nodeIdentityResult(facts Facts) Result {
	result := Result{ID: "node_identity", Label: "Node identity"}
	if facts.Identity == "" && len(facts.TailscaleIPs) == 0 {
		result.Severity = Unknown
		result.Value = "unavailable"
		result.Explanation = "The daemon did not provide a node name or Tailscale IP."
		return result
	}
	result.Severity = Pass
	result.Value = facts.Identity
	if result.Value == "" {
		result.Value = strings.Join(facts.TailscaleIPs, ", ")
	}
	return result
}

func healthResult(warnings []string) Result {
	result := Result{ID: "health", Label: "Health"}
	if len(warnings) == 0 {
		result.Severity = Pass
		result.Value = "no warnings"
		return result
	}
	result.Severity = Warn
	result.Value = fmt.Sprintf("%d warning(s)", len(warnings))
	result.Explanation = strings.Join(warnings, "; ")
	return result
}
