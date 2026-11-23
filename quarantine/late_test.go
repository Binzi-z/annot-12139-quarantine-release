package quarantine_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"quarantine/quarantine"
)

// TestTimedOutAttemptLateResultDiscarded makes attempt 1 ignore cancellation
// and return a clean verdict only after its timeout, then lets attempt 2 return
// an infected verdict. The committed result must be the infected one: the late
// clean answer has no authority.
func TestTimedOutAttemptLateResultDiscarded(t *testing.T) {
	sc := quarantine.NewTestScanner()
	var mu sync.Mutex
	attempts := 0
	lateGate := make(chan struct{})
	sc.SetHandler(func(ctx context.Context, req quarantine.ScanRequest, s *quarantine.TestScanner) (quarantine.ScanOutput, error) {
		mu.Lock()
		attempts++
		n := attempts
		mu.Unlock()
		if n == 1 {
			<-lateGate // ignore ctx; finish late with a misleading clean answer
			return quarantine.ScanOutput{Verdict: quarantine.VerdictClean, Reason: "late clean"}, nil
		}
		return quarantine.ScanOutput{Verdict: quarantine.VerdictInfected, Reason: "second attempt infected"}, nil
	})
	h := newHarness(t, quarantine.Config{MaxAttempts: 2, AttemptTimeout: 5 * time.Second},
		func(c *quarantine.Config) { c.Scanner = sc })
	sub, err := h.e.Submit("tenant-a", content("SIM-CLEAN", "timeout-late"), "")
	if err != nil {
		t.Fatal(err)
	}
	// Let attempt 1 start, then fire its timeout.
	h.sc.WaitEntered(t)
	h.clk.Advance(5 * time.Second)
	// The engine should move on to attempt 2 without waiting for the late
	// answer.
	req2 := h.sc.WaitEntered(t)
	if req2.Attempt != 2 {
		t.Fatalf("second dispatch attempt = %d, want 2", req2.Attempt)
	}
	// Now release the late answer from attempt 1.
	close(lateGate)
	v := h.waitResult("tenant-a", sub.TaskID)
	if v.Result == nil || v.Result.Verdict != quarantine.VerdictInfected {
		t.Fatalf("committed result = %+v, want infected from attempt 2", v.Result)
	}
	if v.Result.Attempt != 2 {
		t.Fatalf("committed attempt = %d, want 2", v.Result.Attempt)
	}
	if _, err := h.e.Release("tenant-a", sub.TaskID); err == nil {
		t.Fatalf("infected result released")
	}
	if got := h.e.ScannerCalls(); got != 2 {
		t.Fatalf("scanner calls = %d, want 2", got)
	}
}

// TestSlotFreedOnTimeout lets a scanner ignore cancellation forever for the
// first attempt. The engine must still free the slot at the timeout commit, so
// other work proceeds.
func TestSlotFreedOnTimeout(t *testing.T) {
	sc := quarantine.NewTestScanner()
	block := make(chan struct{})
	defer close(block)
	sc.SetHandler(func(ctx context.Context, req quarantine.ScanRequest, s *quarantine.TestScanner) (quarantine.ScanOutput, error) {
		if req.Tenant == "tenant-a" {
			<-block // ignore cancellation indefinitely
		}
		return quarantine.ScanOutput{Verdict: quarantine.VerdictClean, Reason: "ok"}, nil
	})
	h := newHarness(t, quarantine.Config{Slots: 3, MaxAttempts: 3, AttemptTimeout: 5 * time.Second},
		func(c *quarantine.Config) { c.Scanner = sc })
	// Occupy one slot with a stuck tenant-a scan.
	if _, err := h.e.Submit("tenant-a", content("SIM-CLEAN", "stuck"), ""); err != nil {
		t.Fatal(err)
	}
	h.sc.WaitEntered(t)
	// Two tenant-b jobs can run in the remaining slots immediately.
	var ids []quarantine.TaskID
	for i := 0; i < 2; i++ {
		s, err := h.e.Submit("tenant-b", content("SIM-CLEAN", fmt.Sprintf("healthy-%d", i)), "")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, s.TaskID)
	}
	for i := 0; i < 2; i++ {
		h.sc.WaitEntered(t)
	}
	// Fire the stuck attempt's timeout; the slot must be returned.
	h.clk.Advance(5 * time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(h.e.EventsOfKind("attempt_failed")) > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if got := len(h.e.EventsOfKind("attempt_failed")); got == 0 {
		t.Fatalf("timeout was not committed")
	}
	// The healthy tenant-b jobs complete from the shared digest cache.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, id := range ids {
		if _, err := h.e.Wait(ctx, "tenant-b", id); err != nil {
			t.Fatalf("tenant-b task %d: %v", id, err)
		}
	}
}
