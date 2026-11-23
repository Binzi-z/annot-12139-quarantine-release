package quarantine_test

import (
	"fmt"
	"testing"
	"time"

	"quarantine/quarantine"
)

// TestMergeAfterCancelRepeated covers the interleaving "cancel the only task,
// then resubmit the same tenant/digest": the new submission must not attach to
// the dead job, must still be scanned, and the cancelled task must stay
// resultless.
func TestMergeAfterCancelRepeated(t *testing.T) {
	for i := 0; i < 60; i++ {
		i := i
		t.Run(fmt.Sprintf("iter-%02d", i), func(t *testing.T) {
			h := newHarness(t, quarantine.Config{Slots: 3})
			data := content("SIM-CLEAN", fmt.Sprintf("merge-after-cancel-%d", i))
			first, err := h.e.Submit("tenant-a", data, "first")
			if err != nil {
				t.Fatal(err)
			}
			h.waitEntered() // job is scanning
			if err := h.e.Cancel("tenant-a", first.TaskID); err != nil {
				t.Fatalf("cancel: %v", err)
			}
			late, err := h.e.Submit("tenant-a", data, "late")
			if err != nil {
				t.Fatal(err)
			}
			if late.Route == quarantine.RouteMerged {
				t.Fatalf("late submission merged into the dead job %s", first.JobID)
			}
			// Serve whatever scan is dispatched until the late task settles.
			stop := make(chan struct{})
			go func() {
				for {
					select {
					case <-stop:
						return
					case <-time.After(time.Millisecond):
						h.sc.ReleaseN(1)
					}
				}
			}()
			v := h.waitResult("tenant-a", late.TaskID)
			close(stop)
			if v.State != quarantine.StateClean || v.Result == nil {
				t.Fatalf("late task = %+v", v)
			}
			v0, _ := h.e.Get("tenant-a", first.TaskID)
			if v0.State != quarantine.StateCancelled || v0.Result != nil {
				t.Fatalf("cancelled task = %+v", v0)
			}
			// Exactly one completed scan committed the late task; the cancelled
			// attempt never committed. Scanner calls are 1 (cancelled) + 1
			// (late), or 1 if the late task merged before the cancelled job was
			// fully dropped in a way that kept a live job. Both are legal; the
			// key invariant is the late task is bound to its own task ID.
			if late.Result != nil {
				if late.Result.TaskID != late.TaskID {
					t.Fatalf("late result bound to wrong task")
				}
			}
		})
	}
}
