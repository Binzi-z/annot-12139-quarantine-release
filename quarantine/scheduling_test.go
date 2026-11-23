package quarantine_test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"quarantine/quarantine"
)

// TestFairnessUnderFloodingTenant has one tenant continuously submit and cancel
// while the other submits a modest amount. With 3 slots and a 2-per-tenant cap
// under contention, the quiet tenant's first job must be dispatched within a
// bounded number of dispatches.
func TestFairnessUnderFloodingTenant(t *testing.T) {
	h := newHarness(t, quarantine.Config{Slots: 3})
	// Two long-running jobs from the noisy tenant occupy slots 0 and 1.
	noisy := make([]quarantine.Submission, 0, 2)
	for i := 0; i < 2; i++ {
		s, err := h.e.Submit("tenant-a", content("SIM-CLEAN", fmt.Sprintf("noisy-%d", i)), "")
		if err != nil {
			t.Fatal(err)
		}
		noisy = append(noisy, s)
	}
	// Wait for both noisy scans to enter.
	for i := 0; i < 2; i++ {
		h.waitEntered()
	}
	// The quiet tenant submits one job; it must be dispatched while the noisy
	// ones are still blocked (the third slot is free).
	quiet, err := h.e.Submit("tenant-b", content("SIM-CLEAN", "quiet"), "")
	if err != nil {
		t.Fatal(err)
	}
	_ = quiet
	// Wait for the quiet job in the dispatch sequence.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		found := false
		for _, ev := range h.e.DispatchSequence() {
			if ev.Tenant == "tenant-b" {
				found = true
				break
			}
		}
		if found {
			break
		}
		time.Sleep(time.Millisecond)
	}
	dispatches := h.e.DispatchSequence()
	quietIdx := -1
	for i, ev := range dispatches {
		if ev.Tenant == "tenant-b" {
			quietIdx = i
			break
		}
	}
	if quietIdx < 0 {
		t.Fatalf("quiet tenant was never dispatched")
	}
	if quietIdx > 6 {
		t.Fatalf("quiet tenant dispatched at position %d, fairness bound exceeded", quietIdx)
	}
	if got := h.e.InflightByTenant()["tenant-a"]; got > 2 {
		t.Fatalf("noisy tenant held %d slots, cap is 2 under contention", got)
	}
	// Release everything and check all complete.
	h.sc.ReleaseN(64)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := h.e.WaitAll(ctx, "tenant-a"); err != nil {
		t.Fatalf("WaitAll a: %v", err)
	}
	if _, err := h.e.WaitAll(ctx, "tenant-b"); err != nil {
		t.Fatalf("WaitAll b: %v", err)
	}
	if got := h.e.Stats().MaxInflight; got > 3 {
		t.Fatalf("max inflight %d > 3", got)
	}
}

// TestCancelStormDoesNotStarveOtherTenant constantly submits and cancels on one
// tenant while a second tenant's work must still complete.
func TestCancelStormDoesNotStarveOtherTenant(t *testing.T) {
	h := newHarness(t, quarantine.Config{Slots: 3})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			s, err := h.e.Submit("tenant-a", content("SIM-CLEAN", fmt.Sprintf("storm-%d", i)), "")
			if err == nil && s.Route == quarantine.RouteNew {
				_ = h.e.Cancel("tenant-a", s.TaskID)
			}
			i++
		}
	}()

	var quiet []quarantine.TaskID
	for i := 0; i < 5; i++ {
		s, err := h.e.Submit("tenant-b", content("SIM-CLEAN", fmt.Sprintf("quiet-%d", i)), "")
		if err != nil {
			t.Fatal(err)
		}
		quiet = append(quiet, s.TaskID)
	}
	// Let the scanner finish normally for whatever is dispatched.
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
				h.sc.ReleaseN(4)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, id := range quiet {
		if _, err := h.e.Wait(ctx, "tenant-b", id); err != nil {
			t.Fatalf("quiet task %d: %v", id, err)
		}
	}
	close(stop)
	wg.Wait()
	h.sc.ReleaseN(64)
	for _, id := range quiet {
		v, err := h.e.Get("tenant-b", id)
		if err != nil {
			t.Fatal(err)
		}
		if v.State != quarantine.StateClean {
			t.Fatalf("quiet task %d state %s", id, v.State)
		}
	}
}

// TestRestartDurability checks that committed results and the rule version
// survive a close/reopen, unfinished tasks become quarantined failures, and the
// same request ID returns the earlier determined result.
func TestRestartDurability(t *testing.T) {
	dir := t.TempDir()
	clk := quarantine.NewManualClock(time.Unix(1700000000, 0))
	sc := quarantine.NewTestScanner()
	e, err := quarantine.NewEngine(quarantine.Config{
		DataDir:        dir,
		Clock:          clk,
		Scanner:        sc,
		Slots:          3,
		MaxAttempts:    2,
		AttemptTimeout: 10 * time.Second,
		Tenants:        []quarantine.Tenant{"tenant-a", "tenant-b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	data := content("SIM-CLEAN", "durable")
	sub, err := e.Submit("tenant-a", data, "req-durable")
	if err != nil {
		t.Fatal(err)
	}
	sc.WaitEntered(t)
	sc.ReleaseN(1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := e.Wait(ctx, "tenant-a", sub.TaskID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Release("tenant-a", sub.TaskID); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := e.UpdateRules(); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen the same directory.
	e2, err := quarantine.NewEngine(quarantine.Config{
		DataDir:        dir,
		Clock:          clk,
		Scanner:        quarantine.NewTestScanner(),
		Slots:          3,
		MaxAttempts:    2,
		AttemptTimeout: 10 * time.Second,
		Tenants:        []quarantine.Tenant{"tenant-a", "tenant-b"},
	})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer e2.Close()
	if got := e2.Rule(); got != 2 {
		t.Fatalf("rule after restart = %d, want 2", got)
	}
	v, err := e2.Get("tenant-a", sub.TaskID)
	if err != nil {
		t.Fatalf("get after restart: %v", err)
	}
	if v.State != quarantine.StateReleased || v.Result == nil || !v.Result.Released {
		t.Fatalf("released task after restart = %+v", v)
	}
	if _, err := os.Stat(v.Result.ReleasePath); err != nil {
		t.Fatalf("release file missing after restart: %v", err)
	}
	// Duplicate request returns the prior determined result.
	dup, err := e2.Submit("tenant-a", data, "req-durable")
	if err != nil {
		t.Fatal(err)
	}
	if dup.Route != quarantine.RouteDuplicate || dup.TaskID != sub.TaskID {
		t.Fatalf("duplicate after restart = %+v", dup)
	}
}
