package quarantine_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"quarantine/quarantine"
)

// TestTimeoutBoundsAttemptsAndStaysQuarantined drives a scanner that never
// answers until its context is cancelled, and advances the manual clock to fire
// attempt timeouts. After MaxAttempts the task must be failed with a bound
// error result, never released, and repeated submissions must be served from
// that sticky result without further scanner calls.
func TestTimeoutBoundsAttemptsAndStaysQuarantined(t *testing.T) {
	h := newHarness(t, quarantine.Config{MaxAttempts: 2, AttemptTimeout: 5 * time.Second})
	sub, err := h.e.Submit("tenant-a", content("SIM-SLOW", "timeout"), "")
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		req := h.waitEntered()
		if req.Attempt != attempt {
			t.Fatalf("attempt = %d, want %d", req.Attempt, attempt)
		}
		// Fire the timeout; the scanner honors ctx and returns.
		h.clk.Advance(5 * time.Second)
		// Wait for the engine to record the failed attempt before the next
		// dispatch.
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) && len(h.e.EventsOfKind("attempt_failed")) < attempt {
			time.Sleep(time.Millisecond)
		}
	}
	v := h.waitState("tenant-a", sub.TaskID, quarantine.StateFailed, 10*time.Second)
	if v.Result == nil || v.Result.Verdict != quarantine.VerdictError {
		t.Fatalf("failed task result = %+v, want bound error", v.Result)
	}
	if v.Result.RuleVersion != 1 {
		t.Fatalf("error result rule = %d", v.Result.RuleVersion)
	}
	if v.Result.Released {
		t.Fatalf("failed task marked released")
	}
	if _, err := h.e.Release("tenant-a", sub.TaskID); err == nil {
		t.Fatalf("failed task was released")
	}
	if got := h.sc.CallsCount(); got != 2 {
		t.Fatalf("scanner calls = %d, want 2 (MaxAttempts)", got)
	}
	// Repeated submission adopts the sticky error result; no new scan.
	sub2, err := h.e.Submit("tenant-a", content("SIM-SLOW", "timeout"), "")
	if err != nil {
		t.Fatal(err)
	}
	if sub2.Result == nil || sub2.Result.Verdict != quarantine.VerdictError {
		t.Fatalf("repeat submission = %+v, want sticky error", sub2)
	}
	if got := h.sc.CallsCount(); got != 2 {
		t.Fatalf("retry after exhaustion made %d scanner calls, want 2", got)
	}
}

// TestFailRetryBounded covers an immediate scanner error (no clock needed) and
// checks the bound.
func TestFailRetryBounded(t *testing.T) {
	sc := quarantine.NewTestScanner()
	sc.SetHandler(func(ctx context.Context, req quarantine.ScanRequest, s *quarantine.TestScanner) (quarantine.ScanOutput, error) {
		return quarantine.ScanOutput{}, errors.New("synthetic failure")
	})
	h := newHarness(t, quarantine.Config{MaxAttempts: 3}, func(c *quarantine.Config) { c.Scanner = sc })
	sub, err := h.e.Submit("tenant-a", content("SIM-FAIL", "fail"), "")
	if err != nil {
		t.Fatal(err)
	}
	v := h.waitState("tenant-a", sub.TaskID, quarantine.StateFailed, 10*time.Second)
	if v.Result == nil || v.Result.Verdict != quarantine.VerdictError {
		t.Fatalf("result = %+v", v.Result)
	}
	if got := sc.CallsCount(); got != 3 {
		t.Fatalf("scanner calls = %d, want 3", got)
	}
	if _, err := h.e.Release("tenant-a", sub.TaskID); err == nil {
		t.Fatalf("failed result released")
	}
	entries, _ := os.ReadDir(h.e.ReleaseDir())
	if len(entries) != 0 {
		t.Fatalf("failed scan produced release files")
	}
}

// TestReleaseWinsBeforeRuleUpdate uses the after-commit hook to block a release
// after its commit point, commits a rule update, then lets the copy finish. The
// release must succeed and the file digest must match.
func TestReleaseWinsBeforeRuleUpdate(t *testing.T) {
	entered := make(chan struct{})
	unblock := make(chan struct{})
	var once sync.Once
	h := newHarness(t, quarantine.Config{}, func(c *quarantine.Config) {
		c.Hooks = &quarantine.TestHooks{
			AfterReleaseCommit: func(id quarantine.TaskID) {
				once.Do(func() { close(entered) })
				<-unblock
			},
		}
		c.Scanner = immediateCleanScanner()
	})
	sub, err := h.e.Submit("tenant-a", content("SIM-CLEAN", "release-wins"), "")
	if err != nil {
		t.Fatal(err)
	}
	v := h.waitResult("tenant-a", sub.TaskID)
	if v.Result == nil || v.Result.Verdict != quarantine.VerdictClean {
		t.Fatalf("no clean result")
	}
	type rel struct {
		info quarantine.ReleaseInfo
		err  error
	}
	done := make(chan rel, 1)
	go func() {
		info, err := h.e.Release("tenant-a", sub.TaskID)
		done <- rel{info, err}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatalf("release never reached its commit point")
	}
	// Release owns the commit point; a rule update may now proceed.
	if _, err := h.e.UpdateRules(); err != nil {
		t.Fatalf("UpdateRules: %v", err)
	}
	close(unblock)
	r := <-done
	if r.err != nil {
		t.Fatalf("release that committed first failed: %v", r.err)
	}
	data, err := os.ReadFile(r.info.Path)
	if err != nil {
		t.Fatalf("released file missing: %v", err)
	}
	if quarantine.DigestBytes(data) != v.Result.Digest {
		t.Fatalf("released digest mismatch")
	}
}

// TestRuleUpdateWinsBeforeRelease uses the before-commit hook to commit a rule
// update before Release takes the lock. The release must then be refused as
// stale and no file may appear.
func TestRuleUpdateWinsBeforeRelease(t *testing.T) {
	var eRef *quarantine.Engine
	h := newHarness(t, quarantine.Config{}, func(c *quarantine.Config) {
		c.Scanner = immediateCleanScanner()
		var once sync.Once
		c.Hooks = &quarantine.TestHooks{
			BeforeReleaseCommit: func(id quarantine.TaskID) {
				once.Do(func() {
					if _, err := eRef.UpdateRules(); err != nil {
						t.Errorf("UpdateRules: %v", err)
					}
				})
			},
		}
	})
	eRef = h.e
	sub, err := h.e.Submit("tenant-a", content("SIM-CLEAN", "rule-wins"), "")
	if err != nil {
		t.Fatal(err)
	}
	h.waitResult("tenant-a", sub.TaskID)
	if _, err := h.e.Release("tenant-a", sub.TaskID); !errors.Is(err, quarantine.ErrStaleResult) {
		t.Fatalf("release = %v, want ErrStaleResult", err)
	}
	entries, _ := os.ReadDir(h.e.ReleaseDir())
	if len(entries) != 0 {
		t.Fatalf("stale release produced %d files", len(entries))
	}
}

// TestReleaseRuleRaceRepeated runs the release/rule race both directions many
// times with real workers, asserting the invariant each round.
func TestReleaseRuleRaceRepeated(t *testing.T) {
	for i := 0; i < 50; i++ {
		i := i
		t.Run(fmt.Sprintf("iter-%02d", i), func(t *testing.T) {
			// Alternate which side commits first.
			releaseFirst := i%2 == 0
			var beforeOnce, afterOnce sync.Once
			entered := make(chan struct{})
			unblock := make(chan struct{})
			var eRef *quarantine.Engine
			h := newHarness(t, quarantine.Config{}, func(c *quarantine.Config) {
				c.Scanner = immediateCleanScanner()
				c.Hooks = &quarantine.TestHooks{
					BeforeReleaseCommit: func(id quarantine.TaskID) {
						beforeOnce.Do(func() {
							if !releaseFirst {
								if _, err := eRef.UpdateRules(); err != nil {
									t.Errorf("UpdateRules: %v", err)
								}
							}
						})
					},
					AfterReleaseCommit: func(id quarantine.TaskID) {
						afterOnce.Do(func() {
							if releaseFirst {
								close(entered)
								<-unblock
							}
						})
					},
				}
			})
			eRef = h.e
			sub, err := h.e.Submit("tenant-a", content("SIM-CLEAN", fmt.Sprintf("race-%d", i)), "")
			if err != nil {
				t.Fatal(err)
			}
			v := h.waitResult("tenant-a", sub.TaskID)
			if v.Result == nil || v.Result.Verdict != quarantine.VerdictClean {
				t.Fatalf("no clean result")
			}

			if !releaseFirst {
				_, err := h.e.Release("tenant-a", sub.TaskID)
				if !errors.Is(err, quarantine.ErrStaleResult) {
					t.Fatalf("rule-first release = %v, want stale", err)
				}
				entries, _ := os.ReadDir(h.e.ReleaseDir())
				if len(entries) != 0 {
					t.Fatalf("rule-first left %d files", len(entries))
				}
				return
			}

			done := make(chan quarantine.ReleaseInfo, 1)
			errc := make(chan error, 1)
			go func() {
				info, err := h.e.Release("tenant-a", sub.TaskID)
				if err != nil {
					errc <- err
					return
				}
				done <- info
			}()
			select {
			case <-entered:
			case err := <-errc:
				t.Fatalf("release failed: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatalf("release did not commit")
			}
			if _, err := h.e.UpdateRules(); err != nil {
				t.Fatalf("UpdateRules: %v", err)
			}
			close(unblock)
			select {
			case info := <-done:
				data, err := os.ReadFile(info.Path)
				if err != nil {
					t.Fatalf("released file missing: %v", err)
				}
				if quarantine.DigestBytes(data) != v.Result.Digest {
					t.Fatalf("released digest mismatch")
				}
			case err := <-errc:
				t.Fatalf("release-first failed: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatalf("release did not finish")
			}
		})
	}
}

// immediateCleanScanner answers clean synchronously.
func immediateCleanScanner() quarantine.Scanner {
	return scannerFunc(func(ctx context.Context, req quarantine.ScanRequest) (quarantine.ScanOutput, error) {
		return quarantine.TestClean(req.Digest), nil
	})
}

type scannerFunc func(ctx context.Context, req quarantine.ScanRequest) (quarantine.ScanOutput, error)

func (f scannerFunc) Scan(ctx context.Context, req quarantine.ScanRequest) (quarantine.ScanOutput, error) {
	return f(ctx, req)
}
