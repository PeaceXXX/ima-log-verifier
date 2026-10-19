package policy

import (
	"testing"

	"github.com/PeaceXXX/ima-log-verifier/pkg/imalog"
)

const digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func entry(path, digest string) imalog.Entry {
	return imalog.Entry{PCRIndex: 10, Template: "ima-ng", FileDigest: digest, Path: path}
}

func load(t *testing.T, s string) *Policy {
	t.Helper()
	p, err := Load([]byte(s))
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return p
}

func TestEvaluateAllowDenyUnknown(t *testing.T) {
	p := load(t, `{
		"default": "unknown",
		"rules": [
			{"path": "/usr/bin/sshd", "digests": ["`+digestA+`"]},
			{"prefix": "/etc/", "digests": ["`+digestA+`", "`+digestB+`"]}
		]
	}`)
	if got := p.Evaluate(entry("/usr/bin/sshd", digestA)); got != Allow {
		t.Fatalf("exact path, known digest: got %s", got)
	}
	if got := p.Evaluate(entry("/usr/bin/sshd", digestB)); got != Deny {
		t.Fatalf("exact path, wrong digest: got %s", got)
	}
	if got := p.Evaluate(entry("/etc/hostname", digestB)); got != Allow {
		t.Fatalf("prefix, known digest: got %s", got)
	}
	if got := p.Evaluate(entry("/etc/hostname", digestA+"x")); got != Deny {
		t.Fatalf("prefix, unknown digest: got %s", got)
	}
	if got := p.Evaluate(entry("/tmp/whatever", digestA)); got != Unknown {
		t.Fatalf("unmatched path: got %s", got)
	}
}

func TestExactPathBeatsPrefix(t *testing.T) {
	p := load(t, `{
		"default": "deny",
		"rules": [
			{"prefix": "/usr/bin/", "digests": ["`+digestA+`"]},
			{"path": "/usr/bin/special", "digests": ["`+digestB+`"]}
		]
	}`)
	if got := p.Evaluate(entry("/usr/bin/special", digestB)); got != Allow {
		t.Fatalf("exact rule should win over prefix, got %s", got)
	}
	if got := p.Evaluate(entry("/usr/bin/other", digestB)); got != Deny {
		t.Fatalf("prefix rule with wrong digest should deny, got %s", got)
	}
}

func TestLongestPrefixWins(t *testing.T) {
	p := load(t, `{
		"default": "unknown",
		"rules": [
			{"prefix": "/srv/", "digests": ["`+digestA+`"]},
			{"prefix": "/srv/app-a/", "digests": ["`+digestB+`"]}
		]
	}`)
	if got := p.Evaluate(entry("/srv/app-a/bin/x", digestB)); got != Allow {
		t.Fatalf("longest prefix should win, got %s", got)
	}
}

func TestSummarize(t *testing.T) {
	p := load(t, `{"default": "unknown", "rules": [{"path": "/bin/ok", "digests": ["`+digestA+`"]}]}`)
	entries := []imalog.Entry{
		entry("/bin/ok", digestA),
		entry("/bin/ok", digestB),
		entry("/bin/mystery", digestA),
	}
	s := p.Summarize(entries)
	if s.Allow != 1 || s.Deny != 1 || s.Unknown != 1 {
		t.Fatalf("bad summary: %+v", s)
	}
}

func TestLoadInvalid(t *testing.T) {
	for name, s := range map[string]string{
		"bad json":       `{oops`,
		"bad default":    `{"default": "maybe", "rules": []}`,
		"rule no target": `{"default": "unknown", "rules": [{"digests": ["` + digestA + `"]}]}`,
		"rule both":      `{"default": "unknown", "rules": [{"path": "/x", "prefix": "/x/", "digests": ["` + digestA + `"]}]}`,
		"rule no digest": `{"default": "unknown", "rules": [{"path": "/x", "digests": []}]}`,
	} {
		if _, err := Load([]byte(s)); err == nil {
			t.Fatalf("%s: expected load error", name)
		}
	}
}
