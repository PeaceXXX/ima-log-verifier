package imalog

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test hex: %v", err)
	}
	return b
}

func TestParseLineValid(t *testing.T) {
	line := "10 f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b ima-ng sha256:abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd /usr/bin/sshd"
	e, ok, err := ParseLine(line, 1)
	if err != nil || !ok {
		t.Fatalf("expected valid entry, got ok=%v err=%v", ok, err)
	}
	if e.PCRIndex != 10 || e.Template != "ima-ng" || e.Path != "/usr/bin/sshd" {
		t.Fatalf("wrong fields: %+v", e)
	}
	if len(e.TemplateHash) != 32 {
		t.Fatalf("template hash not 32 bytes: %d", len(e.TemplateHash))
	}
}

func TestParseLineSkips(t *testing.T) {
	for _, line := range []string{"", "   ", "# a comment", "\t# indented comment"} {
		_, ok, err := ParseLine(line, 1)
		if err != nil || ok {
			t.Fatalf("line %q: expected skip, got ok=%v err=%v", line, ok, err)
		}
	}
}

func TestParseLineMalformed(t *testing.T) {
	cases := []struct {
		name string
		line string
	}{
		{"too few fields", "10 abc ima-ng sha256:xx"},
		{"bad pcr", "xx abc ima-ng sha256:xx /bin/x"},
		{"bad template hash hex", "10 zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz ima-ng sha256:xx /bin/x"},
		{"short template hash", "10 abcd ima-ng sha256:xx /bin/x"},
		{"bad file digest algo", "10 " + strings.Repeat("ab", 32) + " ima-ng md5:xx /bin/x"},
	}
	for _, c := range cases {
		_, _, err := ParseLine(c.line, 7)
		pe, isPE := err.(*ParseError)
		if !isPE {
			t.Fatalf("%s: expected *ParseError, got %v", c.name, err)
		}
		if pe.Line != 7 {
			t.Fatalf("%s: error carries line %d, want 7", c.name, pe.Line)
		}
	}
}

func TestParseStopsAtFirstBadLine(t *testing.T) {
	data := "10 " + strings.Repeat("ab", 32) + " ima-ng sha256:" + strings.Repeat("cd", 32) + " /bin/good\n" +
		"# comment line\n" +
		"\n" +
		"10 " + strings.Repeat("ab", 32) + " ima-ng sha256:" + strings.Repeat("cd", 32) + " /bin/also-good\n" +
		"this is not a log line\n"
	_, err := Parse([]byte(data))
	pe, isPE := err.(*ParseError)
	if !isPE || pe.Line != 5 {
		t.Fatalf("expected ParseError at line 5, got %v", err)
	}
}

func TestReplayChainGolden(t *testing.T) {
	// agg[0] = zeros; agg[1] = SHA256(zeros || zeros) — independently computed.
	entries := []Entry{{PCRIndex: 10, TemplateHash: make([]byte, 32), Template: "ima-ng"}}
	got := hex.EncodeToString(ReplayChain(entries))
	want := "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
	if got != want {
		t.Fatalf("golden chain mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestReplayChainOrder(t *testing.T) {
	one := make([]byte, 32)
	two := bytesRepeat(0x01, 32)
	a := ReplayChain([]Entry{{TemplateHash: one}, {TemplateHash: two}})
	b := ReplayChain([]Entry{{TemplateHash: two}, {TemplateHash: one}})
	if hex.EncodeToString(a) == hex.EncodeToString(b) {
		t.Fatal("chain must be order-sensitive")
	}
	// Two-entry golden vector, independently computed.
	want := "c856842bb0f84d0051e709c65936e1544890dfc8945c873d0b64f4ca8c0ec28b"
	if hex.EncodeToString(a) != want {
		t.Fatalf("2-entry chain mismatch: got %s want %s", hex.EncodeToString(a), want)
	}
}

func TestReplayChainEmpty(t *testing.T) {
	got := ReplayChain(nil)
	if hex.EncodeToString(got) != strings.Repeat("00", 32) {
		t.Fatalf("empty log must replay to the zero aggregate, got %x", got)
	}
}

func TestTamperDetection(t *testing.T) {
	th := sha256.Sum256([]byte("ima-ng|file|/bin/x"))
	entries := []Entry{{PCRIndex: 10, TemplateHash: th[:], Template: "ima-ng", FileDigest: "sha256:00", Path: "/bin/x"}}
	expected := ReplayChain(entries)
	if !VerifyAggregate(entries, expected) {
		t.Fatal("untampered log must verify")
	}
	tampered := []Entry{entries[0]}
	tampered[0].TemplateHash = append([]byte(nil), entries[0].TemplateHash...)
	tampered[0].TemplateHash[31] ^= 0x01 // flip a single bit at the end
	if VerifyAggregate(tampered, expected) {
		t.Fatal("single-bit flip must break the chain")
	}
}

func TestVerifyAggregateHexBadInput(t *testing.T) {
	if _, err := VerifyAggregateHex(nil, "not-hex"); err == nil {
		t.Fatal("expected error for non-hex aggregate")
	}
	if _, err := VerifyAggregateHex(nil, "abcd"); err == nil {
		t.Fatal("expected error for wrong-length aggregate")
	}
}

func TestScopeChain(t *testing.T) {
	mk := func(path string) Entry {
		h := sha256.Sum256([]byte(path))
		return Entry{PCRIndex: 10, TemplateHash: h[:], Template: "ima-ng", Path: path}
	}
	entries := []Entry{mk("/srv/app-a/bin/x"), mk("/srv/app-b/bin/y"), mk("/srv/app-a/bin/z")}
	scoped := ScopeChain(entries, "/srv/app-a/")
	want := ReplayChain([]Entry{entries[0], entries[2]})
	if hex.EncodeToString(scoped) != hex.EncodeToString(want) {
		t.Fatal("scope chain must replay only the prefixed entries, in order")
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
