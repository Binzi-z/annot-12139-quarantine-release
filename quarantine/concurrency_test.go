package quarantine_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"quarantine/quarantine"
)

// harness bundles an engine with a controllable scanner and a manual clock.
type harness struct {
	t   *testing.T
	e   *quarantine.Engine
	sc  *quarantine.TestScanner
	clk *quarantine.ManualClock
}

func newHarness(t *testing.T, cfg quarantine.Config, opts ...func(*quarantine.Config)) *harness {
	t.Helper()
	clk := quarantine.NewManualClock(time.Unix(1700000000, 0))
	sc := quarantine.NewTestScanner()
	if cfg.DataDir == "" {
		cfg.DataDir = t.TempDir()
	}
	cfg.Clock = clk
	cfg.Scanner = sc
	if cfg.Slots == 0 {
		cfg.Slots = 3
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.AttemptTimeout == 0 {
		cfg.AttemptTimeout = 10 * time.Second
	}
	if len(cfg.Tenants) == 0 {
		cfg.Tenants = []quarantine.Tenant{"tenant-a", "tenant-b"}
	}
	for _, o := range opts {
		o(&cfg)
	}
	e, err := quarantine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	h := &harness{t: t, e: e, clk: clk}
	// h.sc always reflects the effective scanner: the injected one when an
	// option replaced it, otherwise the default.
	if ts, ok := cfg.Scanner.(*quarantine.TestScanner); ok {
		h.sc = ts
	} else {
		h.sc = sc
	}
	t.Cleanup(func() { e.Close() })
	return h
}

func content(marker, id string) []byte {
	return []byte("synthetic harmless file " + marker + " id=" + id + "\n")
}

func (h *harness) waitState(tenant quarantine.Tenant, id quarantine.TaskID, want quarantine.TaskState, d time.Duration) quarantine.TaskView {
	h.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		v, err := h.e.Get(tenant, id)
		if err == nil && v.State == want {
			return v
		}
		time.Sleep(2 * time.Millisecond)
	}
	v, _ := h.e.Get(tenant, id)
	h.t.Fatalf("task %d did not reach %s (state %s)", id, want, v.State)
	return v
}

func (h *harness) waitEntered() quarantine.ScanRequest {
	h.t.Helper()
	return h.sc.WaitEntered(h.t)
}

func (h *harness) waitResult(tenant quarantine.Tenant, id quarantine.TaskID) quarantine.TaskView {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	v, err := h.e.Wait(ctx, tenant, id)
	if err != nil {
		h.t.Fatalf("Wait: %v", err)
	}
	return v
}

// TestThreeSlotsBound verifies no more than 3 scans run at once and that all
// work completes once the gate opens.
func TestThreeSlotsBound(t *testing.T) {
	h := newHarness(t, quarantine.Config{})
	for i := 0; i < 6; i++ {
		if _, err := h.e.Submit("tenant-a", content("SIM-CLEAN", fmt.Sprint("a", i)), ""); err != nil {
			t.Fatal(err)
		}
	}
	for seen := 0; seen < 3; seen++ {
		h.waitEntered()
	}
	if got := h.e.Stats().Inflight; got != 3 {
		t.Fatalf("inflight = %d, want 3", got)
	}
	select {
	case <-h.sc.Entered():
		t.Fatalf("a fourth scan started with only 3 slots")
	case <-time.After(80 * time.Millisecond):
	}
	h.sc.ReleaseN(64)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	views, err := h.e.WaitAll(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("WaitAll: %v", err)
	}
	for _, v := range views {
		if v.State != quarantine.StateClean {
			t.Fatalf("task %d state %s", v.TaskID, v.State)
		}
	}
	if got := h.e.ScannerCalls(); got != 6 {
		t.Fatalf("scanner calls = %d, want 6", got)
	}
	if got := h.e.Stats().MaxInflight; got > 3 {
		t.Fatalf("max inflight %d exceeded slots", got)
	}
}

// TestCancelMergedJob cancels one task of a merged job while the shared scan
// continues for the other task. The scan must not restart.
func TestCancelMergedJob(t *testing.T) {
	h := newHarness(t, quarantine.Config{})
	data := content("SIM-CLEAN", "merge")
	s1, err := h.e.Submit("tenant-a", data, "r1")
	if err != nil {
		t.Fatal(err)
	}
	s2, err := h.e.Submit("tenant-a", data, "r2")
	if err != nil {
		t.Fatal(err)
	}
	if s1.JobID != s2.JobID {
		t.Fatalf("expected merged job")
	}
	h.waitEntered()
	if err := h.e.Cancel("tenant-a", s1.TaskID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if v, _ := h.e.Get("tenant-a", s1.TaskID); v.State != quarantine.StateCancelled {
		t.Fatalf("cancelled task state = %s", v.State)
	}
	h.sc.ReleaseN(1)
	v := h.waitResult("tenant-a", s2.TaskID)
	if v.State != quarantine.StateClean {
		t.Fatalf("surviving task state = %s", v.State)
	}
	if got := h.e.ScannerCalls(); got != 1 {
		t.Fatalf("scanner calls = %d, want 1", got)
	}
	if err := h.e.Cancel("tenant-a", s2.TaskID); !errors.Is(err, quarantine.ErrTooLate) {
		t.Fatalf("cancel after commit = %v, want ErrTooLate", err)
	}
}

// TestCancelLastTaskLateResponseDiscarded makes the scanner ignore cancellation
// and return a clean verdict late. That verdict must be discarded.
func TestCancelLastTaskLateResponseDiscarded(t *testing.T) {
	sc := quarantine.NewTestScanner()
	late := make(chan struct{})
	sc.SetHandler(func(ctx context.Context, req quarantine.ScanRequest, s *quarantine.TestScanner) (quarantine.ScanOutput, error) {
		<-late
		return quarantine.ScanOutput{Verdict: quarantine.VerdictClean, Reason: "late clean"}, nil
	})
	h := newHarness(t, quarantine.Config{}, func(c *quarantine.Config) { c.Scanner = sc })
	sub, err := h.e.Submit("tenant-a", content("SIM-CLEAN", "late"), "")
	if err != nil {
		t.Fatal(err)
	}
	sc.WaitEntered(t)
	if err := h.e.Cancel("tenant-a", sub.TaskID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	close(late)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(h.e.EventsOfKind("discard_late")) == 0 {
		time.Sleep(2 * time.Millisecond)
	}
	if got := len(h.e.EventsOfKind("discard_late")); got == 0 {
		t.Fatalf("late response was not recorded as discarded")
	}
	v, _ := h.e.Get("tenant-a", sub.TaskID)
	if v.State != quarantine.StateCancelled {
		t.Fatalf("state = %s, want cancelled", v.State)
	}
	if v.Result != nil {
		t.Fatalf("cancelled task kept result: %+v", v.Result)
	}
	if _, err := h.e.Result("tenant-a", sub.TaskID); err == nil {
		t.Fatalf("cancelled task returned a result")
	}
}
