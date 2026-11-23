package quarantine_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"quarantine/quarantine"
)

// TestRetryBackoffRequiresClockAdvance confirms a failed attempt is not
// immediately redispatched while its backoff is pending; advancing the manual
// clock releases it. This exercises the scheduler's backoff wake-up.
func TestRetryBackoffRequiresClockAdvance(t *testing.T) {
	var calls atomic.Int32
	sc := quarantine.NewTestScanner()
	sc.SetHandler(func(ctx context.Context, req quarantine.ScanRequest, s *quarantine.TestScanner) (quarantine.ScanOutput, error) {
		n := calls.Add(1)
		if n == 1 {
			return quarantine.ScanOutput{}, errors.New("first attempt fails")
		}
		return quarantine.TestClean(req.Digest), nil
	})
	h := newHarness(t, quarantine.Config{
		MaxAttempts:  3,
		RetryBackoff: 3 * time.Second,
	}, func(c *quarantine.Config) { c.Scanner = sc })
	sub, err := h.e.Submit("tenant-a", content("SIM-CLEAN", "backoff"), "")
	if err != nil {
		t.Fatal(err)
	}
	h.sc.WaitEntered(t)
	// Wait for the first attempt's failure to be recorded.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && len(h.e.EventsOfKind("attempt_failed")) == 0 {
		time.Sleep(time.Millisecond)
	}
	// Before advancing, a second attempt must not start.
	select {
	case <-h.sc.Entered():
		t.Fatalf("retry dispatched before backoff elapsed")
	case <-time.After(50 * time.Millisecond):
	}
	// Advance past the backoff; the retry dispatches and succeeds.
	h.clk.Advance(3 * time.Second)
	h.sc.WaitEntered(t)
	v := h.waitResult("tenant-a", sub.TaskID)
	if v.State != quarantine.StateClean {
		t.Fatalf("state = %s, want clean after retry", v.State)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("scanner calls = %d, want 2", got)
	}
}

// TestCancelDuringReleaseIsTooLate ensures that once the release commit point
// is taken, cancellation cannot unwind it.
func TestCancelDuringReleaseIsTooLate(t *testing.T) {
	entered := make(chan struct{})
	unblock := make(chan struct{})
	h := newHarness(t, quarantine.Config{}, func(c *quarantine.Config) {
		c.Scanner = immediateCleanScanner()
		c.Hooks = &quarantine.TestHooks{
			AfterReleaseCommit: func(id quarantine.TaskID) {
				close(entered)
				<-unblock
			},
		}
	})
	sub, err := h.e.Submit("tenant-a", content("SIM-CLEAN", "cancel-release"), "")
	if err != nil {
		t.Fatal(err)
	}
	h.waitResult("tenant-a", sub.TaskID)
	done := make(chan error, 1)
	go func() {
		_, err := h.e.Release("tenant-a", sub.TaskID)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("release never committed")
	}
	// Release is committed; cancel must be refused and the copy must finish.
	if err := h.e.Cancel("tenant-a", sub.TaskID); !errors.Is(err, quarantine.ErrTooLate) {
		t.Fatalf("cancel during release = %v, want ErrTooLate", err)
	}
	close(unblock)
	if err := <-done; err != nil {
		t.Fatalf("release failed after cancel attempt: %v", err)
	}
}

// TestInfectedCacheStickyAcrossDuplicates checks that an infected result is
// reused for repeated submissions under the same rule without new scans, and
// that each duplicate carries its own task ID binding.
func TestInfectedCacheStickyAcrossDuplicates(t *testing.T) {
	sc := quarantine.NewTestScanner()
	sc.SetHandler(func(ctx context.Context, req quarantine.ScanRequest, s *quarantine.TestScanner) (quarantine.ScanOutput, error) {
		return quarantine.ScanOutput{Verdict: quarantine.VerdictInfected, Reason: "sig"}, nil
	})
	h := newHarness(t, quarantine.Config{}, func(c *quarantine.Config) { c.Scanner = sc })
	data := content("SIM-INFECTED", "sticky")
	first, err := h.e.Submit("tenant-a", data, "")
	if err != nil {
		t.Fatal(err)
	}
	h.waitResult("tenant-a", first.TaskID)
	for i := 0; i < 3; i++ {
		s, err := h.e.Submit("tenant-a", data, fmt.Sprintf("dup-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		if s.Route != quarantine.RouteCached {
			t.Fatalf("repeat %d route = %s, want cached", i, s.Route)
		}
		if s.Result == nil || s.Result.Verdict != quarantine.VerdictInfected {
			t.Fatalf("repeat %d result = %+v", i, s.Result)
		}
		if s.TaskID == first.TaskID {
			t.Fatalf("repeat %d reused task id", i)
		}
		if err := s.Result.Validate(); err != nil {
			t.Fatalf("repeat %d binding: %v", i, err)
		}
		if _, err := h.e.Release("tenant-a", s.TaskID); err == nil {
			t.Fatalf("repeat %d released infected result", i)
		}
	}
	if got := sc.CallsCount(); got != 1 {
		t.Fatalf("scanner calls = %d, want 1 (sticky infected)", got)
	}
}
