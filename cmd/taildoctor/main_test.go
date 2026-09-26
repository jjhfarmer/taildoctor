package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jamesfarmer/taildoctor/internal/check"
)

func TestOutcomeExitCode(t *testing.T) {
	for _, test := range []struct {
		name    string
		outcome check.Outcome
		want    int
	}{
		{"usable (PASS or WARN)", check.OutcomeUsable, 0},
		{"definite failure", check.OutcomeDefiniteFail, 1},
		{"unable to establish readiness", check.OutcomeUnreliable, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := exitCode(test.outcome); got != test.want {
				t.Fatalf("exitCode(%q) = %d, want %d", test.outcome, got, test.want)
			}
		})
	}
}

func TestUsableNetworkWarningExitsZero(t *testing.T) {
	report := check.EvaluateNetwork(check.NetworkFacts{
		UDP:                check.ObservationUnavailable,
		DERPTCP443:         check.ObservationAvailable,
		STUNProbeCompleted: true,
		DERPProbeCompleted: true,
	})
	if report.Results[0].Severity != check.Warn || exitCode(report.Outcome) != 0 {
		t.Fatalf("UDP warning: severity = %q, outcome = %q, exit = %d; want WARN, usable, 0",
			report.Results[0].Severity, report.Outcome, exitCode(report.Outcome))
	}
}

func TestInvalidUsageExitCode(t *testing.T) {
	if os.Getenv("TAILDOCTOR_TEST_INVALID_USAGE") == "1" {
		os.Args = []string{"taildoctor", "invalid-command"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInvalidUsageExitCode$")
	cmd.Env = append(os.Environ(), "TAILDOCTOR_TEST_INVALID_USAGE=1")
	output, err := cmd.CombinedOutput()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != usageExitCode {
		t.Fatalf("invalid usage exit = %v, want %d; output: %s", err, usageExitCode, output)
	}
	if !strings.Contains(string(output), "usage: taildoctor check|network|dns") {
		t.Fatalf("missing usage message: %s", output)
	}
}
