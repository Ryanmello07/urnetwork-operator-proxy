package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// The secrets these tests plant in the environment. They are distinctive
// strings so a substring search over the process output is unambiguous.
const (
	testJwtSecret      = "eyJTOPSECRETJWT-do-not-print-me"
	testOperatorSecret = "SUPERSECRET-hunter2-do-not-print-me"
)

var (
	buildOnce sync.Once
	builtBin  string
	buildErr  error
)

// buildProber compiles the CLI once per test binary and returns the path to
// the executable.
//
// These tests deliberately drive the real process rather than calling an
// internal helper: the defect they guard (secrets rendered into flag.Usage
// output) is a property of what the program writes to its own stderr, and
// asserting it end-to-end means the test is independent of how the flags
// happen to be wired internally -- it fails against the pre-fix code and
// keeps failing for any future refactor that reintroduces the leak by another
// route (e.g. logging the parsed values).
func buildProber(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		if _, err := exec.LookPath("go"); err != nil {
			buildErr = err
			return
		}
		// Not t.TempDir(): the binary is shared across tests in this package
		// and must outlive the first test's cleanup.
		dir, err := os.MkdirTemp("", "egress-prober-test")
		if err != nil {
			buildErr = err
			return
		}
		bin := filepath.Join(dir, "egress-prober")
		out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
		if err != nil {
			buildErr = err
			t.Logf("go build output: %s", out)
			return
		}
		builtBin = bin
	})
	if buildErr != nil {
		t.Skipf("cannot build the prober binary in this environment: %s", buildErr)
	}
	return builtBin
}

// runProberWithSecretsInEnv runs the built binary with both secret env vars
// set and returns its combined stdout+stderr.
func runProberWithSecretsInEnv(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(buildProber(t), args...)
	cmd.Env = append(os.Environ(),
		"UR_PROBER_BY_JWT="+testJwtSecret,
		"UR_OPERATOR_SECRET="+testOperatorSecret,
	)
	out, _ := cmd.CombinedOutput() // a non-zero exit is expected in these tests
	return string(out)
}

func assertNoSecrets(t *testing.T, what string, output string) {
	t.Helper()
	if strings.Contains(output, testJwtSecret) {
		t.Errorf("%s printed UR_PROBER_BY_JWT verbatim; the env vars are documented as the way to keep secrets out of logs, and this lands in journald/CI logs.\n--- output ---\n%s", what, output)
	}
	if strings.Contains(output, testOperatorSecret) {
		t.Errorf("%s printed UR_OPERATOR_SECRET verbatim; the env vars are documented as the way to keep secrets out of logs, and this lands in journald/CI logs.\n--- output ---\n%s", what, output)
	}
}

// TestHelpDoesNotPrintSecrets is the regression test for the secret
// disclosure: the flags used to take os.Getenv(...) as their flag DEFAULT, and
// flag.PrintDefaults renders a non-zero default as `(default %q)`. Plain -h
// -- which an operator runs routinely -- therefore echoed both secrets to
// stderr.
func TestHelpDoesNotPrintSecrets(t *testing.T) {
	out := runProberWithSecretsInEnv(t, "-h")
	assertNoSecrets(t, "-h", out)

	// The help must still tell the operator the env vars are supported;
	// suppressing the values must not suppress the documentation.
	for _, name := range []string{"UR_PROBER_BY_JWT", "UR_OPERATOR_SECRET"} {
		if !strings.Contains(out, name) {
			t.Errorf("-h output does not mention %s; the env var is supported and must stay documented.\n--- output ---\n%s", name, out)
		}
	}
}

// TestMissingFlagUsageDoesNotPrintSecrets covers the other, wider trigger:
// any missing required flag prints usage too, and that path is hit whenever a
// deployment is misconfigured -- exactly when the output is most likely to be
// copied into a bug report.
//
// It also proves the env fallback still works: with both secrets supplied
// only via the environment, the "missing required flag(s)" line must name
// -api-url alone.
func TestMissingFlagUsageDoesNotPrintSecrets(t *testing.T) {
	out := runProberWithSecretsInEnv(t, "-platform-url", "wss://example.invalid")
	assertNoSecrets(t, "usage after a missing flag", out)

	missingLine := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "missing required flag") {
			missingLine = line
			break
		}
	}
	if missingLine == "" {
		t.Fatalf("expected a \"missing required flag(s)\" line.\n--- output ---\n%s", out)
	}
	if !strings.Contains(missingLine, "-api-url") {
		t.Errorf("missing-flag line %q should name -api-url", missingLine)
	}
	if strings.Contains(missingLine, "-by-jwt") || strings.Contains(missingLine, "-operator-secret") {
		t.Errorf("missing-flag line %q reports a secret flag as missing, but both were supplied via the environment; the env fallback is broken", missingLine)
	}
}
