package quarantine_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"quarantine/quarantine"
)

func contextWithTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// TestDispatchOrderIsRoundRobin checks that with 3 slots already held by
// tenant-a, a queued tenant-b job is dispatched before tenant-a's fourth job:
// tenant-a is over its 2-slot share under contention, so the other tenant wins
// the freed slot regardless of submission order.
func TestDispatchOrderIsRoundRobin(t *testing.T) {
	h := newHarness(t, quarantine.Config{Slots: 3})
	// Fill all three slots with tenant-a work.
	for i := 0; i < 3; i++ {
		if _, err := h.e.Submit("tenant-a", content("SIM-CLEAN", fmt.Sprintf("fill-%d", i)), ""); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		h.waitEntered()
	}
	if got := h.e.Stats().Inflight; got != 3 {
		t.Fatalf("inflight = %d, want 3", got)
	}
	// Queue tenant-a's fourth job first, then tenant-b's job.
	a4, err := h.e.Submit("tenant-a", content("SIM-CLEAN", "queued-a4"), "")
	if err != nil {
		t.Fatal(err)
	}
	b1, err := h.e.Submit("tenant-b", content("SIM-CLEAN", "queued-b1"), "")
	if err != nil {
		t.Fatal(err)
	}
	if a4.Route == quarantine.RouteMerged || b1.Route == quarantine.RouteMerged {
		t.Fatalf("queued jobs unexpectedly merged")
	}
	// Free one slot; the next dispatch must be tenant-b's job.
	h.sc.ReleaseN(1)
	deadline := time.Now().Add(5 * time.Second)
	var next quarantine.Event
	found := false
	for time.Now().Before(deadline) {
		for _, ev := range h.e.DispatchSequence() {
			if ev.JobID == b1.JobID || ev.JobID == a4.JobID {
				next = ev
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !found {
		t.Fatalf("neither queued job was dispatched")
	}
	if next.JobID != b1.JobID {
		t.Fatalf("first queued dispatch = %s (%s), want tenant-b job %s", next.JobID, next.Tenant, b1.JobID)
	}
	h.sc.ReleaseN(16)
	ctx, cancel := contextWithTimeout(15 * time.Second)
	defer cancel()
	if _, err := h.e.WaitAll(ctx, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.e.WaitAll(ctx, "tenant-b"); err != nil {
		t.Fatal(err)
	}
	if got := h.e.Stats().MaxInflight; got > 3 {
		t.Fatalf("max inflight %d > 3", got)
	}
}

// TestCancelAfterMergeRepeated repeats the merge-then-cancel interleaving many
// times to shake out races in job membership and slot bookkeeping.
func TestCancelAfterMergeRepeated(t *testing.T) {
	for i := 0; i < 60; i++ {
		i := i
		t.Run(fmt.Sprintf("iter-%02d", i), func(t *testing.T) {
			h := newHarness(t, quarantine.Config{Slots: 3})
			digest := fmt.Sprintf("merge-repeat-%d", i)
			data := content("SIM-CLEAN", digest)
			// Submit 4 merged tasks: 1 scan, 4 results.
			var ids []quarantine.TaskID
			var jobID string
			for k := 0; k < 4; k++ {
				s, err := h.e.Submit("tenant-a", data, fmt.Sprintf("m-%d-%d", i, k))
				if err != nil {
					t.Fatal(err)
				}
				if k == 0 {
					jobID = s.JobID
				} else if s.Route != quarantine.RouteMerged || s.JobID != jobID {
					t.Fatalf("task %d route=%s job=%s, want merged into %s", k, s.Route, s.JobID, jobID)
				}
				ids = append(ids, s.TaskID)
			}
			h.waitEntered()
			// Cancel two of the four while scanning; the other two must still
			// receive the single scan's result.
			for _, k := range []int{1, 3} {
				if err := h.e.Cancel("tenant-a", ids[k]); err != nil {
					t.Fatalf("cancel %d: %v", ids[k], err)
				}
			}
			h.sc.ReleaseN(1)
			for _, k := range []int{0, 2} {
				v := h.waitResult("tenant-a", ids[k])
				if v.State != quarantine.StateClean || v.Result == nil {
					t.Fatalf("surviving task %d = %+v", ids[k], v)
				}
				if v.Result.JobID != jobID {
					t.Fatalf("result job %s, want %s", v.Result.JobID, jobID)
				}
			}
			for _, k := range []int{1, 3} {
				v, _ := h.e.Get("tenant-a", ids[k])
				if v.State != quarantine.StateCancelled || v.Result != nil {
					t.Fatalf("cancelled task %d = %+v", ids[k], v)
				}
				if err := h.e.Cancel("tenant-a", ids[k]); !errors.Is(err, quarantine.ErrTooLate) {
					t.Fatalf("re-cancel = %v", err)
				}
			}
			if got := h.e.ScannerCalls(); got != 1 {
				t.Fatalf("scanner calls = %d, want 1", got)
			}
		})
	}
}
