package check

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeFactsProvider struct {
	facts Facts
	err   error
}

func (f fakeFactsProvider) CollectFacts(context.Context) (Facts, error) {
	return f.facts, f.err
}

func resultByID(t *testing.T, report Report, id string) Result {
	t.Helper()
	for _, result := range report.Results {
		if result.ID == id {
			return result
		}
	}
	t.Fatalf("result %q not found", id)
	return Result{}
}

func healthyFacts() Facts {
	return Facts{
		DaemonVersion:     "1.102.5",
		BackendState:      "Running",
		HaveNodeKey:       true,
		Identity:          "james-macbook.example.ts.net",
		TailscaleIPs:      []string{"100.64.0.10"},
		CurrentTailnet:    "example.com",
		CurrentTailnetSet: true,
	}
}

func TestEvaluateKnownBackendStates(t *testing.T) {
	tests := []struct {
		name     string
		state    string
		severity Severity
		outcome  Outcome
	}{
		{name: "running", state: "Running", severity: Pass, outcome: OutcomeUsable},
		{name: "needs login", state: "NeedsLogin", severity: Fail, outcome: OutcomeDefiniteFail},
		{name: "needs machine auth", state: "NeedsMachineAuth", severity: Fail, outcome: OutcomeDefiniteFail},
		{name: "starting", state: "Starting", severity: Warn, outcome: OutcomeUnreliable},
		{name: "stopped", state: "Stopped", severity: Fail, outcome: OutcomeDefiniteFail},
		{name: "no state", state: "NoState", severity: Fail, outcome: OutcomeDefiniteFail},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := healthyFacts()
			facts.BackendState = test.state
			report := Evaluate(facts)
			if got := resultByID(t, report, "backend_state").Severity; got != test.severity {
				t.Fatalf("backend severity = %q, want %q", got, test.severity)
			}
			if report.Outcome != test.outcome {
				t.Fatalf("outcome = %q, want %q", report.Outcome, test.outcome)
			}
		})
	}
}

func TestEvaluateUnknownBackendStateIsUnreliable(t *testing.T) {
	facts := healthyFacts()
	facts.BackendState = "FutureState"
	report := Evaluate(facts)
	if got := resultByID(t, report, "backend_state").Severity; got != Unknown {
		t.Fatalf("backend severity = %q, want %q", got, Unknown)
	}
	if report.Outcome != OutcomeUnreliable {
		t.Fatalf("outcome = %q, want %q", report.Outcome, OutcomeUnreliable)
	}
}

func TestEvaluateAuthenticationActionRequiredOverridesHealthyEvidence(t *testing.T) {
	facts := healthyFacts()
	facts.BackendState = "NeedsLogin"
	facts.AuthURLPresent = true
	report := Evaluate(facts)
	result := resultByID(t, report, "authentication")
	if result.Severity != Fail || result.Value != "action required" {
		t.Fatalf("authentication result = %#v, want action required failure", result)
	}
}

func TestEvaluateHealthWarningsAreUsableWarnings(t *testing.T) {
	facts := healthyFacts()
	facts.HealthWarnings = []string{"UDP connectivity is unavailable"}
	report := Evaluate(facts)
	result := resultByID(t, report, "health")
	if result.Severity != Warn {
		t.Fatalf("health severity = %q, want %q", result.Severity, Warn)
	}
	if report.Outcome != OutcomeUsable {
		t.Fatalf("outcome = %q, want %q", report.Outcome, OutcomeUsable)
	}
}

func TestCollectLocalAPIErrorIsUnreliable(t *testing.T) {
	report, err := Collect(context.Background(), fakeFactsProvider{err: errors.New("connection refused")}, time.Unix(10, 0))
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if report.Outcome != OutcomeUnreliable {
		t.Fatalf("outcome = %q, want %q", report.Outcome, OutcomeUnreliable)
	}
	result := resultByID(t, report, "local_api")
	if result.Severity != Fail {
		t.Fatalf("LocalAPI severity = %q, want %q", result.Severity, Fail)
	}
}

func TestCollectSetsCollectionTime(t *testing.T) {
	now := time.Unix(10, 0)
	report, err := Collect(context.Background(), fakeFactsProvider{facts: healthyFacts()}, now)
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if !report.Facts.CollectedAt.Equal(now) {
		t.Fatalf("CollectedAt = %v, want %v", report.Facts.CollectedAt, now)
	}
}

func TestRenderHealthyOutput(t *testing.T) {
	var output bytes.Buffer
	if err := Render(&output, Evaluate(healthyFacts())); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	text := output.String()
	for _, expected := range []string{
		"Summary: PASS  Tailscale is ready",
		"Supporting evidence:",
		"Backend state     Running",
		"Authentication    authenticated",
		"Descriptive information:",
		"Node identity     james-macbook.example.ts.net",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("output missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "Primary finding:") {
		t.Errorf("healthy output unexpectedly has a primary finding:\n%s", text)
	}
}

func TestRenderNeedsLoginGroupsDependentFindings(t *testing.T) {
	facts := healthyFacts()
	facts.BackendState = "NeedsLogin"
	facts.AuthURLPresent = true
	facts.HealthWarnings = []string{"Tailscale is stopped"}
	var output bytes.Buffer
	if err := Render(&output, Evaluate(facts)); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	text := output.String()
	for _, expected := range []string{
		"Summary: FAIL  Authentication required",
		"Primary finding:",
		"Backend state     NeedsLogin",
		"Supporting evidence:",
		"Authentication    action required",
		"Health            Tailscale is stopped",
		"Descriptive information:",
		"Node identity     james-macbook.example.ts.net",
	} {
		if !strings.Contains(text, expected) {
			t.Errorf("output missing %q:\n%s", expected, text)
		}
	}
	if strings.Contains(text, "covered by backend") {
		t.Errorf("output contains internal dependency wording:\n%s", text)
	}
	if strings.Contains(text, "The node needs authentication") {
		t.Errorf("supporting authentication explanation was repeated:\n%s", text)
	}
}

func TestRenderNeedsMachineAuthOutput(t *testing.T) {
	facts := healthyFacts()
	facts.BackendState = "NeedsMachineAuth"
	var output bytes.Buffer
	if err := Render(&output, Evaluate(facts)); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	text := output.String()
	if !strings.Contains(text, "Summary: FAIL  Machine authorization required") {
		t.Fatalf("specific summary missing:\n%s", text)
	}
}

func TestRenderUnknownBackendOutput(t *testing.T) {
	facts := healthyFacts()
	facts.BackendState = "FutureState"
	var output bytes.Buffer
	if err := Render(&output, Evaluate(facts)); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	text := output.String()
	if !strings.Contains(text, "Summary: UNKNOWN  Unable to establish reliable readiness") {
		t.Fatalf("unknown summary missing:\n%s", text)
	}
}

func TestRenderMultipleHealthWarningsPreservesInformation(t *testing.T) {
	facts := healthyFacts()
	facts.HealthWarnings = []string{"Tailscale is stopped", "DNS configuration is unavailable"}
	var output bytes.Buffer
	if err := Render(&output, Evaluate(facts)); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	text := output.String()
	if !strings.Contains(text, "Health            Tailscale is stopped; DNS configuration is unavailable") {
		t.Fatalf("health warnings missing:\n%s", text)
	}
}

func TestRenderLocalAPIErrorShortCircuits(t *testing.T) {
	report, err := Collect(context.Background(), fakeFactsProvider{err: errors.New("connection refused")}, time.Unix(10, 0))
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	var output bytes.Buffer
	if err := Render(&output, report); err != nil {
		t.Fatalf("Render returned error: %v", err)
	}
	text := output.String()
	if !strings.Contains(text, "Summary: UNKNOWN  Unable to establish reliable readiness") || !strings.Contains(text, "LocalAPI") {
		t.Fatalf("unexpected LocalAPI failure output:\n%s", text)
	}
	if strings.Contains(text, "Backend state") || strings.Contains(text, "Authentication") {
		t.Fatalf("LocalAPI failure rendered downstream diagnostics:\n%s", text)
	}
}
