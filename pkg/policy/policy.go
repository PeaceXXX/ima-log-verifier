// Package policy evaluates IMA log entries against a golden-measurement
// policy expressed as code (JSON). It answers the verifier's second question:
//
//	"Is what was measured the software we expect on this machine?"
//
// A rule names either an exact path or a path prefix and the digests that
// are allowed there. The policy default applies when no rule matches.
//
// Rule evaluation order for an entry:
//  1. exact-path rule wins if one matches;
//  2. otherwise the longest matching prefix rule wins;
//  3. otherwise the policy's DefaultVerdict applies.
package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/PeaceXXX/ima-log-verifier/pkg/imalog"
)

// Verdict is the policy outcome for one measured file.
type Verdict string

const (
	Allow   Verdict = "allow"
	Deny    Verdict = "deny"
	Unknown Verdict = "unknown"
)

// Rule is one policy entry. Exactly one of Path or Prefix must be set.
type Rule struct {
	Path    string   `json:"path,omitempty"`
	Prefix  string   `json:"prefix,omitempty"`
	Digests []string `json:"digests"`
}

// Policy is the full golden-measurement set, decoded from JSON:
//
//	{"default":"unknown","rules":[{"path":"/usr/bin/sshd","digests":["sha256:..."]}, ...]}
type Policy struct {
	DefaultVerdict Verdict `json:"default"`
	Rules          []Rule  `json:"rules"`
}

// Load parses and validates a JSON policy.
func Load(data []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	switch p.DefaultVerdict {
	case Allow, Deny, Unknown:
	default:
		return nil, fmt.Errorf("invalid default verdict %q (want allow|deny|unknown)", p.DefaultVerdict)
	}
	for i, r := range p.Rules {
		if r.Path == "" && r.Prefix == "" {
			return nil, fmt.Errorf("rule %d: one of path or prefix is required", i)
		}
		if r.Path != "" && r.Prefix != "" {
			return nil, fmt.Errorf("rule %d: path and prefix are mutually exclusive", i)
		}
		if len(r.Digests) == 0 {
			return nil, fmt.Errorf("rule %d: at least one digest is required", i)
		}
	}
	return &p, nil
}

// matches reports whether the entry's digest is in the allowed set.
func (r Rule) matches(e imalog.Entry) bool {
	for _, d := range r.Digests {
		if strings.EqualFold(d, e.FileDigest) {
			return true
		}
	}
	return false
}

// Evaluate returns the verdict for one entry.
func (p *Policy) Evaluate(e imalog.Entry) Verdict {
	var bestPrefix *Rule
	bestLen := -1
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Path != "" && r.Path == e.Path {
			if r.matches(e) {
				return Allow
			}
			return Deny
		}
		if r.Prefix != "" && strings.HasPrefix(e.Path, r.Prefix) && len(r.Prefix) > bestLen {
			bestPrefix, bestLen = r, len(r.Prefix)
		}
	}
	if bestPrefix != nil {
		if bestPrefix.matches(e) {
			return Allow
		}
		return Deny
	}
	return p.DefaultVerdict
}

// Summary tallies verdicts over a log.
type Summary struct {
	Allow   int `json:"allow"`
	Deny    int `json:"deny"`
	Unknown int `json:"unknown"`
}

// Summarize evaluates every entry and counts the outcomes.
func (p *Policy) Summarize(entries []imalog.Entry) Summary {
	var s Summary
	for _, e := range entries {
		switch p.Evaluate(e) {
		case Allow:
			s.Allow++
		case Deny:
			s.Deny++
		default:
			s.Unknown++
		}
	}
	return s
}
