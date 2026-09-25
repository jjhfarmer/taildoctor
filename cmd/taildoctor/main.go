package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jamesfarmer/taildoctor/internal/check"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "check" {
		fmt.Fprintln(os.Stderr, "usage: taildoctor check")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

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
