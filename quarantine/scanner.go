package quarantine

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"
)

// ScanRequest is the immutable description handed to a Scanner. Path points at
// the frozen quarantine blob whose SHA-256 must equal Digest.
type ScanRequest struct {
	JobID   string
	Tenant  Tenant
	Digest  Digest
	Rule    RuleVersion
	Attempt int
	Path    string
}

// ScanOutput is a successful scanner answer. A nil error with VerdictClean or
// VerdictInfected commits a result. A non-nil error means the attempt failed and
// may be retried within the engine's bound.
type ScanOutput struct {
	Verdict Verdict
	Reason  string
}

// Scanner is the pluggable scan backend. Implementations must honor ctx: after
// cancellation they should return promptly. The shipped Simulator does.
type Scanner interface {
	Scan(ctx context.Context, req ScanRequest) (ScanOutput, error)
}

// Synthetic markers used by the deterministic simulator. They are plain text
// and are not executable, so demo files are harmless.
const (
	MarkerClean    = "SIM-CLEAN"
	MarkerInfected = "SIM-INFECTED"
	MarkerFail     = "SIM-FAIL"
	MarkerSlow     = "SIM-SLOW"
)

// SimulatorOptions configures the deterministic simulator.
type SimulatorOptions struct {
	// BaseDelay is added to a small digest-derived delay for every scan.
	BaseDelay time.Duration
	// SlowDelay is used for files containing MarkerSlow. It is intended to
	// exceed an engine attempt timeout and therefore exercise timeouts.
	SlowDelay time.Duration
}

// Simulator is the scanner shipped with the project. It only reads the
// synthetic, harmless files placed in quarantine and derives a verdict purely
// from their bytes and the frozen rule version. There is no randomness and no
// network access.
type Simulator struct {
	clock Clock
	opts  SimulatorOptions
}

// NewSimulator returns a deterministic simulator driven by clock.
func NewSimulator(clock Clock, opts SimulatorOptions) *Simulator {
	if clock == nil {
		clock = SystemClock{}
	}
	if opts.SlowDelay <= 0 {
		opts.SlowDelay = 30 * time.Second
	}
	return &Simulator{clock: clock, opts: opts}
}

// delayFor derives a stable, small per-digest delay so parallel scheduling is
// observable while remaining reproducible.
func (s *Simulator) delayFor(d Digest) time.Duration {
	raw, err := hex.DecodeString(string(d))
	if err != nil || len(raw) == 0 {
		return s.opts.BaseDelay
	}
	return s.opts.BaseDelay + time.Duration(raw[0]%5)*time.Millisecond
}

// Scan implements Scanner.
func (s *Simulator) Scan(ctx context.Context, req ScanRequest) (ScanOutput, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	data, err := os.ReadFile(req.Path)
	if err != nil {
		return ScanOutput{}, fmt.Errorf("simulator: read frozen blob: %w", err)
	}
	if got := DigestBytes(data); got != req.Digest {
		return ScanOutput{}, fmt.Errorf("simulator: frozen blob digest mismatch: got %s want %s", got, req.Digest)
	}

	delay := s.delayFor(req.Digest)
	if bytes.Contains(data, []byte(MarkerSlow)) {
		delay = s.opts.SlowDelay
	}
	if delay > 0 {
		select {
		case <-ctx.Done():
			return ScanOutput{}, ctx.Err()
		case <-s.clock.After(delay):
		}
	}
	select {
	case <-ctx.Done():
		return ScanOutput{}, ctx.Err()
	default:
	}

	if bytes.Contains(data, []byte(MarkerFail)) {
		return ScanOutput{}, errors.New("simulator: synthetic scanner failure")
	}
	if bytes.Contains(data, []byte(MarkerInfected)) {
		return ScanOutput{Verdict: VerdictInfected, Reason: "signature matched " + MarkerInfected}, nil
	}
	if bytes.Contains(data, []byte(MarkerClean)) {
		return ScanOutput{Verdict: VerdictClean, Reason: "no signature (" + MarkerClean + ")"}, nil
	}
	return ScanOutput{Verdict: VerdictClean, Reason: "no signature"}, nil
}
