package quarantine

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestManualClockAfter(t *testing.T) {
	clk := NewManualClock(time.Unix(0, 0))
	ch := clk.After(5 * time.Second)
	select {
	case <-ch:
		t.Fatalf("timer fired early")
	case <-time.After(10 * time.Millisecond):
	}
	clk.Advance(4 * time.Second)
	select {
	case <-ch:
		t.Fatalf("timer fired before its deadline")
	case <-time.After(10 * time.Millisecond):
	}
	clk.Advance(time.Second)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("timer did not fire at its deadline")
	}
	if clk.PendingTimers() != 0 {
		t.Fatalf("pending timers = %d, want 0", clk.PendingTimers())
	}
}

func TestManualClockPastDue(t *testing.T) {
	clk := NewManualClock(time.Unix(0, 0))
	ch := clk.After(0)
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("non-positive deadline did not fire immediately")
	}
}

func TestBindingDetectsTampering(t *testing.T) {
	d := DigestBytes([]byte("hello"))
	r := &Result{
		TaskID:      7,
		Tenant:      "tenant-a",
		Digest:      d,
		RuleVersion: 3,
		Verdict:     VerdictClean,
		Binding:     BindingFor(7, "tenant-a", d, 3),
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}
	// Changing any bound field breaks the binding.
	tampered := *r
	tampered.RuleVersion = 4
	if err := tampered.Validate(); err != ErrBindingMismatch {
		t.Fatalf("rule tamper = %v, want binding mismatch", err)
	}
	tampered = *r
	tampered.Tenant = "tenant-b"
	if err := tampered.Validate(); err != ErrBindingMismatch {
		t.Fatalf("tenant tamper = %v, want binding mismatch", err)
	}
	tampered = *r
	tampered.Digest = DigestBytes([]byte("evil"))
	if err := tampered.Validate(); err != ErrBindingMismatch {
		t.Fatalf("digest tamper = %v, want binding mismatch", err)
	}
	tampered = *r
	tampered.TaskID = 8
	if err := tampered.Validate(); err != ErrBindingMismatch {
		t.Fatalf("task tamper = %v, want binding mismatch", err)
	}
}

func TestSimulatorDeterministicAndHarmless(t *testing.T) {
	dir := t.TempDir()
	data := []byte("synthetic harmless SIM-CLEAN payload")
	d := DigestBytes(data)
	p := dir + string(os.PathSeparator) + string(d)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	clk := NewManualClock(time.Unix(0, 0))
	sim := NewSimulator(clk, SimulatorOptions{})
	req := ScanRequest{Digest: d, Path: p, Rule: 1}
	type out struct {
		o ScanOutput
		e error
	}
	done := make(chan out, 2)
	for i := 0; i < 2; i++ {
		go func() {
			o, e := sim.Scan(context.Background(), req)
			done <- out{o, e}
		}()
	}
	// Both calls wait on the manual clock; release their delays.
	deadline := time.Now().Add(2 * time.Second)
	for clk.PendingTimers() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	clk.Advance(time.Hour)
	var got []ScanOutput
	for i := 0; i < 2; i++ {
		r := <-done
		if r.e != nil {
			t.Fatalf("scan: %v", r.e)
		}
		got = append(got, r.o)
	}
	if got[0] != got[1] {
		t.Fatalf("simulator not deterministic: %+v", got)
	}
	if got[0].Verdict != VerdictClean {
		t.Fatalf("verdict = %s, want clean", got[0].Verdict)
	}
}

func TestSimulatorRejectsDigestMismatch(t *testing.T) {
	dir := t.TempDir()
	data := []byte("synthetic harmless SIM-CLEAN payload")
	p := dir + string(os.PathSeparator) + "blob"
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	sim := NewSimulator(nil, SimulatorOptions{})
	_, err := sim.Scan(context.Background(), ScanRequest{Digest: DigestBytes([]byte("other")), Path: p})
	if err == nil {
		t.Fatalf("simulator accepted a mismatched digest")
	}
}

func TestNormalizeDigest(t *testing.T) {
	d := DigestBytes([]byte("x"))
	got, err := NormalizeDigest(string(d))
	if err != nil || got != d {
		t.Fatalf("normalize = %q, %v", got, err)
	}
	upper := "ABCDEF"
	if _, err := NormalizeDigest(upper); err == nil {
		t.Fatalf("accepted short digest")
	}
}
