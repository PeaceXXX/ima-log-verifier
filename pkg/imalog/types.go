// Package imalog models and parses Linux IMA measurement logs in their ASCII
// format, and replays the PCR-style aggregate chain a verifier uses to check
// a log against the aggregate bound into attestation evidence.
//
// The ASCII log format is documented in the public Linux kernel
// Documentation/security/IMA.txt:
//
//	PCRindex template-hash-hex template-name filedata-hash filename-hint
//
// e.g.:
//
//	10 d9b2b8dc7e8c37c2b92a38e30f3cd28... ima-ng sha256:abcd... /usr/bin/sshd
//
// Verification here is *replay and reconstruct*: starting from an aggregate
// of 32 zero bytes, each entry's template hash is folded in with
// SHA256(prev || templateHash). The resulting aggregate is then compared in
// constant time against the aggregate the attestor bound into its evidence
// (for example a TPM quote). A log that does not replay to the expected
// aggregate was tampered with, truncated, or reordered.
package imalog

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

// Entry is one parsed IMA measurement record.
type Entry struct {
	PCRIndex     uint   // PCR the measurement was extended into
	TemplateHash []byte // template digest that the PCR was extended with
	Template     string // IMA template name, e.g. "ima-ng"
	FileDigest   string // file-data digest, "sha256:<hex>"
	Path         string // file path (filename-hint)
}

// Log is an ordered sequence of parsed IMA entries.
type Log struct {
	Entries []Entry
}

// ZeroAggregate is the 32-byte all-zero start of a measurement chain.
var ZeroAggregate = make([]byte, sha256.Size)

// ReplayChain recomputes the aggregate chain over entries:
//
//	agg[0]   = 32 zero bytes
//	agg[i+1] = SHA256(agg[i] || entry[i].TemplateHash)
//
// It returns agg[len(entries)]; for an empty log that is the zero aggregate.
// This mirrors how a TPM extends PCRs and how a verifier reconstructs the
// expected aggregate from the log alone, without trusting it.
func ReplayChain(entries []Entry) []byte {
	agg := bytes.Clone(ZeroAggregate)
	for _, e := range entries {
		h := sha256.New()
		h.Write(agg)
		h.Write(e.TemplateHash)
		agg = h.Sum(nil)
	}
	return agg
}

// ScopeChain replays only the entries whose path carries the given prefix,
// modeling a per-container (or per-workload) measurement chain folded out of
// the host-wide log.
func ScopeChain(entries []Entry, prefix string) []byte {
	var scoped []Entry
	for _, e := range entries {
		if len(e.Path) >= len(prefix) && e.Path[:len(prefix)] == prefix {
			scoped = append(scoped, e)
		}
	}
	return ReplayChain(scoped)
}

// VerifyAggregate reports whether entries replay to the expected aggregate,
// comparing in constant time so a verifier's comparison does not leak which
// prefix of the log diverged via timing.
func VerifyAggregate(entries []Entry, expected []byte) bool {
	computed := ReplayChain(entries)
	return subtle.ConstantTimeCompare(computed, expected) == 1
}

// VerifyAggregateHex is VerifyAggregate with a hex-decoded aggregate.
func VerifyAggregateHex(entries []Entry, expectedHex string) (bool, error) {
	expected, err := DecodeHexBytes(expectedHex, sha256.Size)
	if err != nil {
		return false, fmt.Errorf("expected aggregate: %w", err)
	}
	return VerifyAggregate(entries, expected), nil
}
