package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jamesfarmer/taildoctor/internal/check"
)

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "check" && os.Args[1] != "network" && os.Args[1] != "dns") {
		fmt.Fprintln(os.Stderr, "usage: taildoctor check|network|dns")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if os.Args[1] == "dns" {
		report := check.CollectDNS(ctx, check.NewDNSClient(), time.Now())
		if err := check.RenderDNS(os.Stdout, report); err != nil {
			os.Exit(1)
		}
		if report.Outcome != check.OutcomeUsable {
			os.Exit(1)
		}
		return
	}

	if os.Args[1] == "network" {
		report := check.CollectNetwork(ctx, check.NewNetworkClient(), time.Now())
		if err := check.RenderNetwork(os.Stdout, report); err != nil {
			os.Exit(1)
		}
		if report.Outcome != check.OutcomeUsable {
			os.Exit(1)
		}
		return
	}

	report, err := check.Collect(ctx, check.NewClient(), time.Now())
	if err != nil {
		os.Exit(1)
	}

	if err := check.Render(os.Stdout, report); err != nil {
		os.Exit(1)
	}
	if report.Outcome != check.OutcomeUsable {
		os.Exit(1)
	}
}
