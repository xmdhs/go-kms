package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPrintUsage(t *testing.T) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	printUsage()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	_ = r.Close()
	if !strings.Contains(buf.String(), "Usage:") {
		t.Fatalf("usage output missing Usage: %q", buf.String())
	}
}

// TestHelperProcess is the subprocess entry: it runs main() with a fabricated
// argv so the tested binary's os.Exit calls end this child process.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	os.Args = strings.Split(os.Getenv("HELPER_ARGV"), "|")
	main()
	os.Exit(0)
}

func runHelper(t *testing.T, argv ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "HELPER_ARGV="+strings.Join(argv, "|"))
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run helper: %v", err)
	}
	return out.String(), code
}

func TestMainNoArgs(t *testing.T) {
	out, code := runHelper(t, "go-kms")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(out, "Usage:") {
		t.Fatalf("expected usage output, got %q", out)
	}
}

func TestMainUnknownCommand(t *testing.T) {
	out, code := runHelper(t, "go-kms", "bogus")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(out, "Usage:") {
		t.Fatalf("expected usage output, got %q", out)
	}
}

func TestMainClientList(t *testing.T) {
	out, code := runHelper(t, "go-kms", "client", "--mode=list")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "Available product modes:") {
		t.Fatalf("expected product list, got %q", out)
	}
}
