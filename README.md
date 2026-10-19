# ima-log-verifier

A verifier-side engine for Linux IMA runtime integrity: replay an IMA
measurement log, recompute the PCR-style aggregate chain, compare it against
the aggregate bound into attestation evidence, and evaluate every measured
file against a golden-measurement policy. It also verifies per-scope chains
(filtered by path prefix), the model for per-container measurement chains
inside a host-wide log.

Go standard library only. Clean-room implementation built on the public
Linux kernel IMA ASCII log format; every fixture in `testdata/` is synthetic
and generated in-repo.

## Why this exists

Boot attestation tells you the kernel that booted was the expected one. It
says nothing about what ran *after* boot. Linux IMA (Integrity Measurement
Architecture) closes that gap: the kernel measures each file it loads and
extends a PCR-style aggregate chain, appending an event log entry per
measurement.

The verifier's job is **replay and reconstruct, not trust the log**:

1. Parse the log.
2. Replay the chain from scratch: `agg[i+1] = SHA256(agg[i] || templateHash[i])`.
3. Compare the result — in constant time — against the aggregate the
   attestor bound into its evidence (e.g. a TPM quote). If they differ, the
   log was tampered with, truncated, or reordered. Tamper evidence, not
   tamper resistance: the chain makes modification *detectable*.
4. Check *what* was measured against a golden-measurement policy
   (policy-as-code): expected digest per path, allow-listed digests per
   prefix, and a default verdict.

## Architecture

```
┌──────────┐   synthetic log    ┌──────────────┐   replay chain   ┌────────────┐
│ ima-gen  ├───────────────────►│  ima-verify  ├─────────────────►│  verdict   │
│(fixture  │                    │              │   compare vs     │  (exit 0/2)│
│ builder) │   ┌────────────┐   │  ┌────────┐  │   evidence       └────────────┘
└──────────┘   │ quote.json │──►│  │policy  │◄──┐
               │ nonce,     │   │  │engine  │   │ golden digests
               │ aggregate,│   │  └────────┘  ─┘
               │ scopes{...}│   └──────────────┘
               └────────────┘
```

`ima-gen` produces deterministic fixtures (same `--seed` → byte-identical
output): `good.log`, `tampered.log` (one template hash bit-flipped),
`violating.log` (one out-of-policy digest appended), plus `policy.json` and
a `quote.json` fixture carrying a nonce, the expected aggregate, and
per-scope aggregates. `ima-verify` never trusts the log — it replays it.

## Quickstart

Build:

```sh
go build ./...
```

Generate fixtures (deterministic; committed copies live in `testdata/`):

```sh
go run ./cmd/ima-gen --seed 42 --count 24 \
  --out good.log --policy-out policy.json --quote-out quote.json \
  --tamper-index 5 --violate \
  --scope-prefix /srv/app-a/
# generated 24 entries -> good.log (+ policy policy.json, quote quote.json)
```

Verify the good log — exit 0:

```sh
go run ./cmd/ima-verify --log testdata/good.log \
  --policy testdata/policy.json --quote testdata/quote.json
# entries:   24
# aggregate: edf2ce764f7bf44f7cb006b5aaeeb61f0db003e842e6706adbd6ec0770556b83
# chain:     OK (replayed aggregate matches evidence)
# policy:    allow=24 deny=0 unknown=0
# verdict:   verified
```

Verify the tampered log — exit 2 (chain mismatch; policy is still clean):

```sh
go run ./cmd/ima-verify --log testdata/tampered.log \
  --policy testdata/policy.json --quote testdata/quote.json
# entries:   24
# aggregate: 4de4806a18275e7eee2e287061a40a2d6a10d2f834b69e9e1a2dbc41bd0abb73
# chain:     MISMATCH (log was tampered, truncated, or reordered)
# policy:    allow=24 deny=0 unknown=0
# verdict:   failed
```

Verify the violating log — exit 2 (unknown binary `/tmp/unknown-evil`;
note the chain also mismatches because the quote binds the original
24-entry log):

```sh
go run ./cmd/ima-verify --log testdata/violating.log \
  --policy testdata/policy.json --quote testdata/quote.json
# entries:   25
# aggregate: 9fb6cfab96c08216e5d1e71153061d44d61d0a7f4cf3308ec132f3c8779ed0bb
# chain:     MISMATCH (log was tampered, truncated, or reordered)
# policy:    allow=24 deny=0 unknown=1
# verdict:   failed
```

Verify one container's scope against its own bound aggregate — exit 0:

```sh
go run ./cmd/ima-verify --log testdata/good.log \
  --policy testdata/policy.json --quote testdata/quote.json \
  --scope-prefix /srv/app-a/
# entries:   12
# aggregate: f27625ef07c19962edc22376a06502b458e420f7ac4e374dc39f5569f1417382
# chain:     OK (replayed aggregate matches evidence)
# policy:    allow=12 deny=0 unknown=0
# verdict:   verified
```

If an *in-scope* entry is tampered, the scope chain fails while other
scopes are untouched — this is the per-container isolation property:

```sh
go run ./cmd/ima-gen --seed 42 --count 24 --out /tmp/sg.log \
  --policy-out /tmp/sp.json --quote-out /tmp/sq.json \
  --tamper-index 4 --tampered-out /tmp/st.log \
  --scope-prefix /srv/app-a/
go run ./cmd/ima-verify --log /tmp/st.log --policy /tmp/sp.json \
  --quote /tmp/sq.json --scope-prefix /srv/app-a/
# entries:   12
# aggregate: aa215bb9f0d0d25577b755b108cfa25192bcdc5ec435602230bad5264d2da5c9
# chain:     MISMATCH (log was tampered, truncated, or reordered)
# policy:    allow=12 deny=0 unknown=0
# verdict:   failed
```

JSON output and verbose per-entry verdicts:

```sh
go run ./cmd/ima-verify --log testdata/good.log \
  --policy testdata/policy.json --quote testdata/quote.json --format json
# {
#   "entries": 24,
#   "aggregate": "edf2ce764f7bf44f7cb006b5aaeeb61f0db003e842e6706adbd6ec0770556b83",
#   "chain_ok": true,
#   "policy": { "allow": 24, "deny": 0, "unknown": 0 },
#   "verdict": "verified"
# }

go run ./cmd/ima-verify --log testdata/violating.log \
  --policy testdata/policy.json --quote testdata/quote.json -v | tail -2
# allow   /usr/bin/python3 sha256:4d24513957566e7c0ddd655d3eebbbb82a863f3c7fd80d7450bf31ec2bbf7633
# unknown /tmp/unknown-evil sha256:7f096c6ea6297cc3713feb509cc3013240bb5df4abcb1782b2bd0e9f71586cc5
```

## CLI reference

### ima-gen — deterministic fixture builder

| Flag | Default | Meaning |
|---|---|---|
| `--seed` | 42 | deterministic seed; same seed → byte-identical output |
| `--count` | 24 | number of log entries |
| `--out` | `good.log` | good-log path |
| `--policy-out` | `policy.json` | golden-measurement policy path |
| `--quote-out` | `quote.json` | quote fixture path |
| `--tamper-index` | -1 | entry whose template hash to flip (`-1`: no tampered variant) |
| `--tampered-out` | `tampered.log` | tampered-log path |
| `--violate` | false | also emit a log with one out-of-policy digest |
| `--violating-out` | `violating.log` | violating-log path |
| `--scope-prefix` | "" | prefix under which half the entries live (per-scope chains) |

### ima-verify — the verifier

| Flag | Default | Meaning |
|---|---|---|
| `--log` | (required) | IMA ASCII log file |
| `--policy` | (required) | JSON golden-measurement policy file |
| `--aggregate` | "" | expected aggregate as hex (takes precedence over `--quote`) |
| `--quote` | "" | quote fixture JSON; with `--scope-prefix` uses `scopes[prefix]` |
| `--scope-prefix` | "" | verify only the per-prefix chain (per-container model) |
| `--format` | `text` | `text` or `json` |
| `--strict` | false | fail on `unknown` verdicts too, not just denies |
| `-v` | false | print per-entry `<verdict> <path> <digest>` lines |

Exit codes: **0** verified (chain OK, no denies — and no unknowns with
`--strict`); **2** verification failed; **1** usage/IO error (bad flags,
unreadable files, malformed log/policy).

### Policy format

```json
{
  "default": "unknown",
  "rules": [
    {"path": "/usr/bin/sshd", "digests": ["sha256:…"]},
    {"prefix": "/etc/", "digests": ["sha256:…", "sha256:…"]}
  ]
}
```

Evaluation: exact-path rule wins; otherwise the longest matching prefix
rule wins; otherwise the policy default (`allow`|`deny`|`unknown`) applies.
Digests are compared case-insensitively.

## Library usage

```go
import (
    "os"
    "github.com/PeaceXXX/ima-log-verifier/pkg/imalog"
    "github.com/PeaceXXX/ima-log-verifier/pkg/policy"
)

data, _ := os.ReadFile("good.log")
log, err := imalog.Parse(data)          // line numbers on malformed input
if err != nil { /* exit 1 */ }

ok, err := imalog.VerifyAggregateHex(log.Entries, expectedHex) // constant-time
if err != nil || !ok { /* exit 2: tampered / truncated / reordered */ }

pdata, _ := os.ReadFile("policy.json")
pol, _ := policy.Load(pdata)
summary := pol.Summarize(log.Entries)    // allow / deny / unknown counts
```

## What this demonstrates

- **Binary/text format parsing** — the IMA ASCII log format parsed strictly:
  five fields, hex-validated, `sha256:`-prefixed digests, comments and blank
  lines skipped, and every parse error carrying its line number.
- **Hash-chain replay** — reconstructing a PCR-style aggregate from the log
  alone (`agg[i+1] = SHA256(agg[i] || templateHash)`), order-sensitive, with
  a golden vector in the tests.
- **Tamper evidence** — a single flipped bit breaks the chain; the verifier
  detects modification rather than preventing it, and compares in constant
  time (`subtle.ConstantTimeCompare`).
- **Policy-as-code** — golden measurements as versioned JSON: exact-path
  rules, longest-prefix matching, deny/allow/unknown tri-state, strict mode
  for zero-unknown deployments.
- **Deterministic fixtures** — a seeded PRNG generator produces byte-identical
  logs, policies, and quote fixtures so tests and demos are reproducible.
- **Per-container scoping** — path-prefix chains model per-workload
  measurement chains folded out of one host log, verified against their own
  bound aggregates.

## Limitations / how I'd productionize it

- **Real evidence parsing.** The quote fixture stands in for a real TPM/TEE
  quote; production would parse actual quote structures and verify signatures
  over the nonce + aggregate, not just compare hex.
- **Custom IMA templates.** Only the classic `ima-ng` template shape is
  modeled. Real deployments use custom templates (e.g. carrying cgroup info
  for per-container binding) that need their own parsers and a template-hash
  recomputation from the raw fields.
- **Freshness binding.** A nonce is generated but never bound to the chain
  cryptographically — the fixture doesn't sign `(nonce, aggregate)`. The
  industry discussion of freshness-gap attacks applies: without evidence
  expiry and a signed nonce, a stale-but-valid attestation can be replayed.
- **Key management.** No keys anywhere here; production needs a KMS/HSM for
  the verifier's signing keys and policy-signing so policies themselves are
  authenticated.
- **Streaming.** The log is parsed into memory. Million-entry logs from real
  hosts need a streaming parser and incremental chain replay.
- **No kernel interaction.** This reads logs as files; a production agent
  would read `/sys/kernel/security/ima/ascii_runtime_measurements` and bind
  the read to the quote atomically.

## Clean-room statement

This project is built entirely from public concepts and general engineering
knowledge: the IMA ASCII log format is documented in the public Linux kernel
documentation, and all sample logs, digests, policies, and quotes are
synthetic data generated in-repo. It contains no Intel-internal code, APIs,
or non-public details.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 Rihui Tan.
