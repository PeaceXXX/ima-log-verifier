// End-to-end: generate fixtures with ima-gen, then verify them with
// ima-verify — good (exit 0), tampered (exit 2), violating (exit 2).
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// moduleRoot returns the repo root (parent of the cmd/ tree) from the
// location of this test file.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}

// runBin runs an already-built binary with cwd=dir and returns exit code.
func runBin(t *testing.T, dir, bin string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("run %s: %v", bin, err)
		}
	}
	return code, string(out)
}

func TestEndToEnd(t *testing.T) {
	root := moduleRoot(t)
	tmp := t.TempDir()

	// Build both binaries once; `go run` would mask the child exit code.
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	genBin := filepath.Join(binDir, "ima-gen")
	verifyBin := filepath.Join(binDir, "ima-verify")
	for _, target := range []struct{ pkg, out string }{
		{"./cmd/ima-gen", genBin},
		{"./cmd/ima-verify", verifyBin},
	} {
		cmd := exec.Command("go", "build", "-o", target.out, target.pkg)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", target.pkg, err, out)
		}
	}

	log := filepath.Join(tmp, "good.log")
	pol := filepath.Join(tmp, "policy.json")
	quote := filepath.Join(tmp, "quote.json")
	tampered := filepath.Join(tmp, "tampered.log")
	violating := filepath.Join(tmp, "violating.log")

	// 1. Deterministic fixtures: same seed twice -> byte-identical log.
	gen := func(seed string) {
		code, output := runBin(t, root, genBin,
			"--seed", seed, "--count", "24",
			"--out", log, "--policy-out", pol, "--quote-out", quote,
			"--tamper-index", "5", "--tampered-out", tampered,
			"--violate", "--violating-out", violating,
			"--scope-prefix", "/srv/app-a/")
		if code != 0 {
			t.Fatalf("ima-gen exit %d: %s", code, output)
		}
	}
	gen("42")
	first, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	gen("42")
	second, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("ima-gen is not deterministic for seed 42")
	}

	verify := func(args ...string) (int, string) {
		return runBin(t, root, verifyBin, args...)
	}
	base := []string{"--log", log, "--policy", pol, "--quote", quote}

	// 2. Good log verifies.
	if code, out := verify(base...); code != 0 {
		t.Fatalf("good log: want exit 0, got %d:\n%s", code, out)
	}
	// 3. Tampered log fails chain verification.
	if code, out := verify("--log", tampered, "--policy", pol, "--quote", quote); code != 2 {
		t.Fatalf("tampered log: want exit 2, got %d:\n%s", code, out)
	}
	// 4. Violating log fails policy verification (chain is fine here).
	if code, out := verify("--log", violating, "--policy", pol, "--quote", quote); code != 2 {
		t.Fatalf("violating log: want exit 2, got %d:\n%s", code, out)
	}
	// 5. Per-scope verification: scope chain vs the fixture's scope aggregate.
	scopeArgs := []string{"--log", log, "--policy", pol, "--quote", quote, "--scope-prefix", "/srv/app-a/"}
	if code, out := verify(scopeArgs...); code != 0 {
		t.Fatalf("scope verify: want exit 0, got %d:\n%s", code, out)
	}
	// 6. Wrong scope aggregate must fail.
	if code, out := verify(append(scopeArgs, "--aggregate", "00")...); code != 1 && code != 2 {
		t.Fatalf("bad aggregate: want nonzero exit, got %d:\n%s", code, out)
	}
	// 7. --strict on a clean policy+log passes.
	if code, out := verify(append(base, "--strict")...); code != 0 {
		t.Fatalf("strict good log: want exit 0, got %d:\n%s", code, out)
	}
}
