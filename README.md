# Taildoctor

Taildoctor is an open-source diagnostic CLI for troubleshooting Tailscale
connectivity on employee and infrastructure devices.

It collects facts from Tailscale, interprets them cautiously, and presents
operator-focused findings for IT and support engineers.

> Taildoctor is an independent community project and is not affiliated with
> or maintained by Tailscale.

## What It Does

Currently implemented:

- `taildoctor check` — local daemon, backend/authentication readiness, and health
- `taildoctor network` — UDP/STUN and DERP TCP/443 network readiness

## Example

```text
$ taildoctor network

Summary: PASS  Network readiness looks healthy

Supporting evidence:
	UDP connectivity    available
	DERP TCP/443        reachable
	NAT mapping         stable

Network information:
	IPv4 STUN           observed
	IPv6 STUN           observed
	OS IPv6             observed
	Fastest DERP        lhr
	TCP/443 latency     8ms
```

## Why Taildoctor?

Tailscale already provides excellent low-level diagnostic tools:

| Tool | Purpose |
| --- | --- |
| `tailscale status` | Inspect local node and peer state |
| `tailscale netcheck` | Expose detailed network probe results |
| `tailscale bugreport` | Mark and correlate diagnostics for Tailscale Support |
| **Taildoctor** | Interpret selected evidence into operator-focused findings |

Taildoctor complements these tools; it does not replace them.

Its niche is interpretation:

```text
observed fact -> diagnostic interpretation -> suggested investigation
```

It deliberately avoids claiming a root cause when the available evidence does
not prove one.

The project was inspired by
[Tailscale issue #18943](https://github.com/tailscale/tailscale/issues/18943).

## `taildoctor check`

Checks whether the local Tailscale installation appears fundamentally ready to
operate.

It currently examines:

- LocalAPI availability
- Tailscale backend state
- authentication and machine authorization state
- local node identity
- Tailscale IP addresses
- daemon health warnings

Example:

```text
Summary: FAIL  Authentication required

Primary finding:
	Backend state     NeedsLogin
										The Tailscale node is not authenticated.
										Recommendation: Sign in with Tailscale before retrying.

Supporting evidence:
	Authentication    action required
	Health            Tailscale is stopped.

Descriptive information:
	Node identity     James’s MacBook Pro
```

## `taildoctor network`

Performs a fresh active probe based on Tailscale's network-checking behavior.
It examines two meaningful Tailscale paths:

- UDP/STUN capability, relevant to direct peer-to-peer connectivity
- DERP TCP/443 reachability, which provides relay fallback

It also reports supporting observations such as IPv4/IPv6 STUN results, local
IPv6 socket support, fastest observed DERP region, DERP TCP/443 latency, and
destination-dependent NAT mapping behavior.

The command does not claim that a failed UDP probe proves firewall blocking,
or that a successful STUN probe guarantees a direct path to a particular peer.

## Build And Run

Taildoctor currently requires Go 1.26.6 or newer.

Build the CLI:

```sh
go build -o taildoctor ./cmd/taildoctor
```

Run the commands during development:

```sh
go run ./cmd/taildoctor check
go run ./cmd/taildoctor network
```

The local Tailscale client must be installed and its LocalAPI must be
available. Taildoctor uses the LocalAPI rather than parsing human-readable
Tailscale CLI output.

## Exit codes

Taildoctor separates the diagnostic status shown to a human from the overall
readiness outcome and the shell process exit code. Currently, for `check`,
`network`, and `dns`:

| Diagnostic status | Overall outcome | Exit |
| --- | --- | ---: |
| PASS — healthy | Usable | 0 |
| WARN — usable, but needs attention | Usable | 0 |
| FAIL — definite problem established | Definite failure | 1 |
| UNKNOWN — reliable readiness not established | Unable to establish readiness | 1 |

WARN can still exit 0: exit status reflects whether the requested diagnostic
produced a usable result, not whether every individual result was PASS. UNKNOWN
means the evidence was insufficient, rather than proving a definite failure.
Invalid CLI usage exits 2. Collection or output errors also exit 1.

## Design Philosophy

Taildoctor separates:

1. **Observed facts** — values returned by Tailscale or measured by a probe
2. **Interpretation** — what those facts suggest about Tailscale operation
3. **Recommendations** — what an operator might investigate next

For example:

```text
Observed fact:
	UDP STUN round trip was not established.

Interpretation:
	Direct peer-to-peer connectivity may be limited.

Possible causes:
	NAT behavior, filtering, another VPN, routing, packet loss, or a
	temporary network condition.
```

The implementation keeps vendor-specific Tailscale types behind collection
adapters and evaluates Taildoctor-owned facts. Each diagnostic area is built
as a small, independently testable vertical slice.

## Privacy And Security

Privacy is part of the design rather than a later cleanup task.

- Do not display node private keys or public keys.
- Do not display authentication URLs.
- Do not shell out to parse human-readable Tailscale output.
- Prefer Tailscale's supported public Go APIs and LocalAPI.
- Keep raw Tailscale types behind collection adapters.
- Avoid collecting peer data unless a diagnostic requires it.
- Do not send diagnostic data anywhere.
- Do not modify Tailscale configuration.

The current network output does not display public STUN-observed addresses.
Support bundles and machine-readable output are not implemented yet, so their
redaction rules remain future work.

## Platform Status

Taildoctor is designed to be cross-platform. Development and current smoke
testing have been performed on macOS; Windows and Linux validation is planned.

The commands require a running Tailscale installation with accessible LocalAPI
permissions. The `network` command also requires an active network because it
performs fresh STUN and DERP TCP/443 probes.

The project currently uses Tailscale `v1.102.5` and Go `1.26.6`.
The `tailscale.com/net/netcheck` package is public and tagged, but does not
carry the same explicit stability guarantees as the stable LocalAPI methods.
That dependency is deliberate and documented as a compatibility risk.

## Current Limitations

- There is no JSON output.
- There is no support-bundle command.
- There are no DNS diagnostics.
- There are no peer reachability diagnostics.
- The network command does not test connectivity to a particular peer.
- UDP/STUN results do not prove that a specific peer can or cannot connect
	directly.
- DERP latency is descriptive and has no built-in high-latency threshold.
- The network command does not identify a specific firewall product or claim
	that a firewall is blocking traffic.
- Active probe failures can result from temporary conditions and may be
	UNKNOWN when the evidence is incomplete.

## Roadmap

Planned diagnostic areas include:

- DNS and MagicDNS diagnostics
- peer-specific reachability diagnostics
- deeper authentication and machine-authorization diagnostics
- human-readable support bundles
- machine-readable output
- broader interpretation of Tailscale health and route information

The roadmap is intentionally incremental. Each area should begin with a small
vertical slice, focused tests, and an explicit review of API stability and
privacy impact.

## Development

Run tests:

```sh
go test ./...
```

Run static analysis:

```sh
go vet ./...
```

The development approach is:

1. understand the relevant Tailscale API and data structures
2. define a small diagnostic model
3. separate collection from interpretation
4. write focused tests
5. implement the smallest useful vertical slice
6. document assumptions and limitations

Taildoctor should remain a focused tool for diagnosing a Tailscale problem,
not become a general-purpose Tailscale administration or monitoring system.
Taildoctor is an open-source, cross-platform diagnostic CLI for Tailscale.
