// Command ima-gen builds deterministic synthetic IMA logs, a matching
// golden-measurement policy, and a quote fixture — everything needed to demo
// the verifier without touching a real machine or real measurement data.
//
// Determinism: the same --seed produces byte-identical output, so fixtures
// can be committed and CI can replay them. All digests are pseudo-random
// hex, not hashes of real files.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/PeaceXXX/ima-log-verifier/pkg/imalog"
	"github.com/PeaceXXX/ima-log-verifier/pkg/policy"
)

// hostFiles is the pool of host paths the generator draws from.
var hostFiles = []string{
	"/usr/bin/sshd", "/usr/bin/systemd", "/usr/lib/libc.so.6",
	"/etc/ssh/sshd_config", "/etc/passwd", "/etc/hostname",
	"/usr/sbin/nginx", "/etc/nginx/nginx.conf", "/usr/bin/docker",
	"/usr/bin/containerd", "/usr/bin/bash", "/usr/bin/python3",
}

type quoteFixture struct {
	Nonce     string            `json:"nonce"`
	Aggregate string            `json:"aggregate"`
	Scopes    map[string]string `json:"scopes"`
}

// prng is a deterministic xorshift64* generator; same seed -> same stream.
type prng struct{ state uint64 }

func (r *prng) next() uint64 {
	x := r.state
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	r.state = x
	return x * 0x2545F4914F6CDD1D
}

func (r *prng) bytes(n int) []byte {
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(r.next() >> 56)
	}
	return b
}

func (r *prng) intn(n int) int { return int(r.next() % uint64(n)) }

func main() {
	seed := flag.Uint64("seed", 42, "deterministic seed; same seed -> same output")
	count := flag.Int("count", 24, "number of log entries to generate")
	out := flag.String("out", "good.log", "path for the good log")
	policyOut := flag.String("policy-out", "policy.json", "path for the golden-measurement policy")
	quoteOut := flag.String("quote-out", "quote.json", "path for the quote fixture")
	tamperIndex := flag.Int("tamper-index", -1, "index of the entry whose template hash to alter in the tampered variant (-1: skip tampered variant)")
	tamperedOut := flag.String("tampered-out", "tampered.log", "path for the tampered log variant")
	violate := flag.Bool("violate", false, "also emit a violating log variant with one out-of-policy digest")
	violatingOut := flag.String("violating-out", "violating.log", "path for the violating log variant")
	scopePrefix := flag.String("scope-prefix", "", "prefix under which half the entries live, e.g. /srv/app-a/")
	flag.Parse()

	r := &prng{state: *seed}

	// 1. Generate the entries. First half land under --scope-prefix when set.
	entries := make([]imalog.Entry, 0, *count)
	paths := make([]string, 0, *count)
	for i := 0; i < *count; i++ {
		var path string
		if *scopePrefix != "" && i%2 == 0 {
			path = *scopePrefix + "bin/app-" + fmt.Sprint(i/2)
		} else {
			path = hostFiles[r.intn(len(hostFiles))]
		}
		fileDigest := "sha256:" + hex.EncodeToString(r.bytes(sha256.Size))
		// The template hash must be consistent with fileDigest the way a real
		// IMA template hash is derived from the measured data; here we define
		// it as SHA256("ima-ng|" + fileDigest + "|" + path).
		tmplHash := sha256.Sum256([]byte("ima-ng|" + fileDigest + "|" + path))
		entries = append(entries, imalog.Entry{
			PCRIndex:     10,
			TemplateHash: tmplHash[:],
			Template:     "ima-ng",
			FileDigest:   fileDigest,
			Path:         path,
		})
		paths = append(paths, path)
	}

	// 2. Golden-measurement policy covering every generated digest exactly.
	// A path may be measured more than once with different digests (e.g. the
	// same pool entry drawn twice); the rule carries every digest the
	// generator emitted for that path.
	byPath := map[string][]string{}
	var order []string
	for _, e := range entries {
		if _, ok := byPath[e.Path]; !ok {
			order = append(order, e.Path)
		}
		byPath[e.Path] = append(byPath[e.Path], e.FileDigest)
	}
	exactRules := make([]policy.Rule, 0, len(order))
	for _, p := range order {
		exactRules = append(exactRules, policy.Rule{Path: p, Digests: byPath[p]})
	}
	pol := policy.Policy{DefaultVerdict: policy.Unknown, Rules: exactRules}

	// 3. Write good.log.
	writeLog(*out, entries)

	// 4. Policy + quote fixture with matching aggregates.
	polJSON, err := json.MarshalIndent(pol, "", "  ")
	must(err)
	writeFile(*policyOut, polJSON)

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		must(err)
	}
	scopes := map[string]string{}
	if *scopePrefix != "" {
		scopes[*scopePrefix] = hex.EncodeToString(imalog.ScopeChain(entries, *scopePrefix))
	}
	q := quoteFixture{
		Nonce:     hex.EncodeToString(nonce),
		Aggregate: hex.EncodeToString(imalog.ReplayChain(entries)),
		Scopes:    scopes,
	}
	qJSON, err := json.MarshalIndent(q, "", "  ")
	must(err)
	writeFile(*quoteOut, qJSON)

	// 5. Tampered variant: flip one byte of one template hash.
	if *tamperIndex >= 0 {
		if *tamperIndex >= len(entries) {
			fail(fmt.Sprintf("tamper-index %d out of range (0..%d)", *tamperIndex, len(entries)-1))
		}
		t := make([]imalog.Entry, len(entries))
		copy(t, entries)
		t[*tamperIndex].TemplateHash = append([]byte(nil), t[*tamperIndex].TemplateHash...)
		t[*tamperIndex].TemplateHash[0] ^= 0xff
		writeLog(*tamperedOut, t)
	}

	// 6. Violating variant: one entry whose digest matches no policy rule.
	if *violate {
		v := make([]imalog.Entry, len(entries), len(entries)+1)
		copy(v, entries)
		fd := "sha256:" + hex.EncodeToString(r.bytes(sha256.Size))
		th := sha256.Sum256([]byte("ima-ng|" + fd + "|/tmp/unknown-evil"))
		v = append(v, imalog.Entry{
			PCRIndex:     10,
			TemplateHash: th[:],
			Template:     "ima-ng",
			FileDigest:   fd,
			Path:         "/tmp/unknown-evil",
		})
		writeLog(*violatingOut, v)
	}

	fmt.Printf("generated %d entries -> %s (+ policy %s, quote %s)\n", len(entries), *out, *policyOut, *quoteOut)
}

// writeLog serializes entries in IMA ASCII format.
func writeLog(path string, entries []imalog.Entry) {
	var sb strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&sb, "%d %s %s %s %s\n",
			e.PCRIndex, hex.EncodeToString(e.TemplateHash), e.Template, e.FileDigest, e.Path)
	}
	writeFile(path, []byte(sb.String()))
}

func writeFile(path string, data []byte) {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		must(os.MkdirAll(dir, 0o755))
	}
	must(os.WriteFile(path, data, 0o644))
}

func must(err error) {
	if err != nil {
		fail(err.Error())
	}
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "ima-gen: "+msg)
	os.Exit(1)
}
