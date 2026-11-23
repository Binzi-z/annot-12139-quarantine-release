package quarantine

import (
	"context"
	"sync"
	"time"
)

// This file is the project's test-support kit. It is intentionally part of the
// package rather than a _test.go file: the concurrency tests are written in the
// external quarantine_test package and drive real workers through these
// controls. Nothing here is used by the normal engine path.

// TestHooks lets a test halt a release on either side of its commit point. The
// callbacks run on the goroutine calling Release.
type TestHooks struct {
	// BeforeReleaseCommit runs before Release takes the engine lock.
	BeforeReleaseCommit func(taskID TaskID)
	// AfterReleaseCommit runs after the release commit point, before the
	// verified copy. Blocking here must not prevent a rule update from
	// committing, and the already-committed copy must still finish.
	AfterReleaseCommit func(taskID TaskID)
}

// TestScanner is a controllable Scanner for concurrency tests. Each call
// announces itself on Entered, then either waits for a token (ReleaseN) or for
// ctx cancellation. SetHandler can replace this behavior entirely.
type TestScanner struct {
	mu      sync.Mutex
	calls   int
	entered chan ScanRequest
	tokens  chan struct{}
	handler func(ctx context.Context, req ScanRequest, s *TestScanner) (ScanOutput, error)
}

// NewTestScanner returns a blocking TestScanner.
func NewTestScanner() *TestScanner {
	return &TestScanner{
		entered: make(chan ScanRequest, 256),
		tokens:  make(chan struct{}, 256),
	}
}

// SetHandler replaces the default wait-for-token behavior.
func (s *TestScanner) SetHandler(f func(ctx context.Context, req ScanRequest, s *TestScanner) (ScanOutput, error)) {
	s.mu.Lock()
	s.handler = f
	s.mu.Unlock()
}

// CallsCount returns the number of started calls.
func (s *TestScanner) CallsCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// Entered returns the channel of started requests.
func (s *TestScanner) Entered() <-chan ScanRequest { return s.entered }

// ReleaseN lets n waiting calls proceed. Extra tokens are retained for calls
// that have not started yet.
func (s *TestScanner) ReleaseN(n int) {
	for i := 0; i < n; i++ {
		s.tokens <- struct{}{}
	}
}

// WaitEntered blocks for the next started request.
func (s *TestScanner) WaitEntered(t interface{ Fatalf(string, ...any) }) ScanRequest {
	select {
	case r := <-s.entered:
		return r
	case <-time.After(10 * time.Second):
		t.Fatalf("scanner was not entered within 10s")
		return ScanRequest{}
	}
}

// Scan implements Scanner.
func (s *TestScanner) Scan(ctx context.Context, req ScanRequest) (ScanOutput, error) {
	s.mu.Lock()
	s.calls++
	h := s.handler
	s.mu.Unlock()

	select {
	case s.entered <- req:
	default:
	}
	if h != nil {
		return h(ctx, req, s)
	}
	select {
	case <-ctx.Done():
		return ScanOutput{}, ctx.Err()
	case <-s.tokens:
		return TestClean(req.Digest), nil
	}
}

// TestClean derives a deterministic clean verdict from a digest.
func TestClean(d Digest) ScanOutput {
	reason := "test clean"
	if len(d) >= 8 {
		reason += " " + string(d)[:8]
	}
	return ScanOutput{Verdict: VerdictClean, Reason: reason}
}
