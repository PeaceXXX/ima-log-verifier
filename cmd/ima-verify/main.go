// Command ima-verify checks an IMA measurement log the way a remote
// verifier would:
//
//  1. Parse the log.
//  2. Replay the aggregate chain and compare it (constant time) against the
//     aggregate bound into attestation evidence (--aggregate hex or a quote
//     fixture --quote). If --scope-prefix is set, verify the per-scope chain
//     instead — the model for per-container measurement chains.
//  3. Evaluate every measured file against a golden-measurement policy.
//
// Exit codes: 0 verified (chain OK, no denies; with --strict also no
// unknowns), 2 verification failed, 1 usage/IO error.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/PeaceXXX/ima-log-verifier/pkg/imalog"
	"github.com/PeaceXXX/ima-log-verifier/pkg/policy"
)

const (
	exitOK       = 0 // verified
	exitUsage    = 1 // bad flags / unreadable inputs
	exitMismatch = 2 // verification failed
)

type quoteFixture struct {
	Nonce     string            `json:"nonce"`
	Aggregate string            `json:"aggregate"`
	Scopes    map[string]string `json:"scopes"`
}

type jsonReport struct {
	Entries   int    `json:"entries"`
	Aggregate string `json:"aggregate"`
	ChainOK   bool   `json:"chain_ok"`
	Policy    struct {
		Allow   int `json:"allow"`
		Deny    int `json:"deny"`
		Unknown int `json:"unknown"`
	} `json:"policy"`
	Verdict string `json:"verdict"`
}

func main() {
	logPath := flag.String("log", "", "IMA ASCII log file (required)")
	policyPath := flag.String("policy", "", "JSON golden-measurement policy file (required)")
	aggregate := flag.String("aggregate", "", "expected aggregate as hex (use with or instead of --quote)")
	quotePath := flag.String("quote", "", "quote fixture JSON providing the expected aggregate")
	scopePrefix := flag.String("scope-prefix", "", "verify only the per-scope chain for this path prefix")
	format := flag.String("format", "text", "output format: text|json")
	strict := flag.Bool("strict", false, "fail if any entry is unknown to the policy")
	verbose := flag.Bool("v", false, "print a per-entry verdict line")
	flag.Parse()

	if *logPath == "" || *policyPath == "" {
		usage("--log and --policy are required")
	}
	if *format != "text" && *format != "json" {
		usage("--format must be text or json")
	}

	logData, err := os.ReadFile(*logPath)
	if err != nil {
		fail(fmt.Sprintf("read log: %v", err))
	}
	parsed, err := imalog.Parse(logData)
	if err != nil {
		fail(fmt.Sprintf("parse log: %v", err))
	}

	polData, err := os.ReadFile(*policyPath)
	if err != nil {
		fail(fmt.Sprintf("read policy: %v", err))
	}
	pol, err := policy.Load(polData)
	if err != nil {
		fail(fmt.Sprintf("load policy: %v", err))
	}

	// Select the expected aggregate: --aggregate wins; otherwise the quote
	// fixture; with --scope-prefix the fixture's per-scope aggregate is used.
	expected := *aggregate
	if expected == "" && *quotePath != "" {
		q, err := loadQuote(*quotePath)
		if err != nil {
			fail(fmt.Sprintf("load quote: %v", err))
		}
		if *scopePrefix != "" {
			hexAgg, ok := q.Scopes[*scopePrefix]
			if !ok {
				fail(fmt.Sprintf("quote has no scope %q", *scopePrefix))
			}
			expected = hexAgg
		} else {
			expected = q.Aggregate
		}
	}
	if expected == "" {
		usage("one of --aggregate or --quote is required")
	}

	var entries []imalog.Entry
	if *scopePrefix != "" {
		for _, e := range parsed.Entries {
			if len(e.Path) >= len(*scopePrefix) && e.Path[:len(*scopePrefix)] == *scopePrefix {
				entries = append(entries, e)
			}
		}
	} else {
		entries = parsed.Entries
	}

	chainOK, err := imalog.VerifyAggregateHex(entries, expected)
	if err != nil {
		fail(fmt.Sprintf("bad expected aggregate: %v", err))
	}
	computedHex := hex.EncodeToString(imalog.ReplayChain(entries))

	summary := pol.Summarize(entries)
	if *verbose {
		for _, e := range entries {
			fmt.Printf("%-7s %s %s\n", pol.Evaluate(e), e.Path, e.FileDigest)
		}
	}

	verified := chainOK && summary.Deny == 0 && (!*strict || summary.Unknown == 0)
	verdict := "verified"
	if !verified {
		verdict = "failed"
	}

	switch *format {
	case "json":
		var r jsonReport
		r.Entries = len(entries)
		r.Aggregate = computedHex
		r.ChainOK = chainOK
		r.Policy.Allow = summary.Allow
		r.Policy.Deny = summary.Deny
		r.Policy.Unknown = summary.Unknown
		r.Verdict = verdict
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fail(err.Error())
		}
	default:
		fmt.Printf("entries:   %d\n", len(entries))
		fmt.Printf("aggregate: %s\n", computedHex)
		if chainOK {
			fmt.Println("chain:     OK (replayed aggregate matches evidence)")
		} else {
			fmt.Println("chain:     MISMATCH (log was tampered, truncated, or reordered)")
		}
		fmt.Printf("policy:    allow=%d deny=%d unknown=%d\n", summary.Allow, summary.Deny, summary.Unknown)
		fmt.Printf("verdict:   %s\n", verdict)
	}

	if !verified {
		os.Exit(exitMismatch)
	}
}

func loadQuote(path string) (quoteFixture, error) {
	var q quoteFixture
	data, err := os.ReadFile(path)
	if err != nil {
		return q, err
	}
	if err := json.Unmarshal(data, &q); err != nil {
		return q, err
	}
	return q, nil
}

func usage(msg string) {
	fmt.Fprintln(os.Stderr, "ima-verify: "+msg)
	flag.Usage()
	os.Exit(exitUsage)
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "ima-verify: "+msg)
	os.Exit(exitUsage)
}
