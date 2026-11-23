package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"quarantine/quarantine"
)

// captureStdout runs fn and returns what it wrote to os.Stdout.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		done <- buf.String()
	}()
	runErr := fn()
	w.Close()
	os.Stdout = old
	out := <-done
	return out, runErr
}

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCLIEndToEnd drives submit -> result -> release -> rules across separate
// in-process invocations sharing one data directory, verifying durable state
// and the JSON contract.
func TestCLIEndToEnd(t *testing.T) {
	dir := t.TempDir()
	clean := writeFile(t, dir, "clean.bin", []byte("synthetic harmless file SIM-CLEAN cli\n"))
	infected := writeFile(t, dir, "bad.bin", []byte("synthetic harmless file SIM-INFECTED cli\n"))

	out, err := captureStdout(t, func() error {
		return run([]string{"submit", "-data", dir, "-tenant", "tenant-a", "-file", clean, "-request", "cli-1", "-json"})
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	var sub quarantine.Submission
	if err := json.Unmarshal([]byte(out), &sub); err != nil {
		t.Fatalf("decode submit: %v\n%s", err, out)
	}
	if sub.State != quarantine.StateClean || sub.Result == nil || sub.Result.Verdict != quarantine.VerdictClean {
		t.Fatalf("submit result = %+v", sub)
	}
	// Duplicate request across a new process returns the same determined task.
	out, err = captureStdout(t, func() error {
		return run([]string{"submit", "-data", dir, "-tenant", "tenant-a", "-file", clean, "-request", "cli-1", "-json"})
	})
	if err != nil {
		t.Fatalf("duplicate submit: %v", err)
	}
	var dup quarantine.Submission
	if err := json.Unmarshal([]byte(out), &dup); err != nil {
		t.Fatal(err)
	}
	if dup.Route != quarantine.RouteDuplicate || dup.TaskID != sub.TaskID {
		t.Fatalf("duplicate = %+v, want task %d", dup, sub.TaskID)
	}

	// Result query across a new process.
	out, err = captureStdout(t, func() error {
		return run([]string{"result", "-data", dir, "-tenant", "tenant-a", "-task", itoa(sub.TaskID), "-json"})
	})
	if err != nil {
		t.Fatalf("result: %v", err)
	}
	var res quarantine.Result
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if err := res.Validate(); err != nil {
		t.Fatalf("binding: %v", err)
	}

	// Release across a new process, then verify the file's actual digest.
	out, err = captureStdout(t, func() error {
		return run([]string{"release", "-data", dir, "-tenant", "tenant-a", "-task", itoa(sub.TaskID), "-json"})
	})
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	var info quarantine.ReleaseInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(info.Path)
	if err != nil {
		t.Fatalf("read release: %v", err)
	}
	if quarantine.DigestBytes(b) != res.Digest {
		t.Fatalf("release digest mismatch")
	}

	// Infected submission cannot be released.
	out, err = captureStdout(t, func() error {
		return run([]string{"submit", "-data", dir, "-tenant", "tenant-a", "-file", infected, "-json"})
	})
	if err != nil {
		t.Fatalf("infected submit: %v", err)
	}
	var bad quarantine.Submission
	if err := json.Unmarshal([]byte(out), &bad); err != nil {
		t.Fatal(err)
	}
	if bad.Result == nil || bad.Result.Verdict != quarantine.VerdictInfected {
		t.Fatalf("infected submit = %+v", bad)
	}
	if err := run([]string{"release", "-data", dir, "-tenant", "tenant-a", "-task", itoa(bad.TaskID)}); err == nil {
		t.Fatalf("infected release succeeded")
	}

	// Rule update, then a previously-clean-but-unreleased old-rule result is
	// stale. Submit a second clean file under rule 1 first.
	clean2 := writeFile(t, dir, "clean2.bin", []byte("synthetic harmless file SIM-CLEAN cli2\n"))
	out, err = captureStdout(t, func() error {
		return run([]string{"submit", "-data", dir, "-tenant", "tenant-b", "-file", clean2, "-json"})
	})
	if err != nil {
		t.Fatalf("submit2: %v", err)
	}
	var sub2 quarantine.Submission
	if err := json.Unmarshal([]byte(out), &sub2); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"rules", "-data", dir, "-update"}); err != nil {
		t.Fatalf("rules update: %v", err)
	}
	if err := run([]string{"release", "-data", dir, "-tenant", "tenant-b", "-task", itoa(sub2.TaskID)}); err == nil {
		t.Fatalf("stale release succeeded after rule update")
	}
	// The already-released task remains idempotently released.
	if err := run([]string{"release", "-data", dir, "-tenant", "tenant-a", "-task", itoa(sub.TaskID)}); err != nil {
		t.Fatalf("idempotent re-release: %v", err)
	}
}

func TestCLIListAndSlots(t *testing.T) {
	dir := t.TempDir()
	f := writeFile(t, dir, "a.bin", []byte("synthetic harmless file SIM-CLEAN list\n"))
	if err := run([]string{"submit", "-data", dir, "-tenant", "tenant-a", "-file", f}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	out, err := captureStdout(t, func() error {
		return run([]string{"list", "-data", dir, "-tenant", "tenant-a", "-json"})
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var views []quarantine.TaskView
	if err := json.Unmarshal([]byte(out), &views); err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].Tenant != "tenant-a" {
		t.Fatalf("list = %+v", views)
	}
	out, err = captureStdout(t, func() error {
		return run([]string{"slots", "-data", dir, "-json"})
	})
	if err != nil {
		t.Fatalf("slots: %v", err)
	}
	var st quarantine.Stats
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatal(err)
	}
	if st.Slots != 3 {
		t.Fatalf("slots = %d, want 3", st.Slots)
	}
	// Other tenant cannot see tenant-a's task.
	if err := run([]string{"status", "-data", dir, "-tenant", "tenant-b", "-task", "1"}); err == nil {
		t.Fatalf("cross-tenant status succeeded")
	}
}

func TestCLIDemo(t *testing.T) {
	dir := t.TempDir()
	out, err := captureStdout(t, func() error {
		return run([]string{"demo", "-out", dir, "-json"})
	})
	if err != nil {
		t.Fatalf("demo: %v", err)
	}
	if !strings.Contains(out, "\"scanner_calls\"") {
		t.Fatalf("demo did not emit JSON report")
	}
}

func itoa(id quarantine.TaskID) string {
	const digits = "0123456789"
	if id == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for id > 0 {
		i--
		b[i] = digits[id%10]
		id /= 10
	}
	return string(b[i:])
}
