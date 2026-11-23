// Package quarantine implements a local, content-addressed file quarantine with
// two tenants sharing a fixed pool of parallel scan workers.
//
// The package is deliberately built around explicit commit points:
//
//   - A scan result is committed under the engine lock only while the job is
//     still live (not cancelled) and the attempt that produced it is still the
//     current attempt. Late responses from abandoned attempts are discarded.
//   - A release is committed under the same lock. It requires a clean result
//     whose RuleVersion equals the engine's current rule version at that
//     instant. A rule update that wins the lock first therefore makes the
//     release stale; a release that wins may finish copying after the update.
//   - Cancellation is committed under the lock. Once committed, a scan result
//     arriving later can no longer attach. Once a result is committed,
//     cancellation is refused (too late).
//
// The physical quarantine blob is immutable for the lifetime of a task: it is
// named by the SHA-256 of its content, frozen at upload time, and never
// rewritten. Every copy to the release directory is re-hashed, so the digest in
// the release directory proves what was actually released.
package quarantine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Tenant identifies one of the isolated tenants sharing the scanner pool.
type Tenant string

// Digest is the lower-case hex SHA-256 of a frozen upload.
type Digest string

// TaskID is the identifier of one submission. Distinct submissions keep
// distinct task IDs even when they share an underlying scan.
type TaskID uint64

// RuleVersion is the version of the scanner rule set.
type RuleVersion int64

// Verdict is the outcome of a scan.
type Verdict string

const (
	VerdictClean    Verdict = "clean"
	VerdictInfected Verdict = "infected"
	VerdictError    Verdict = "error"
)

// TaskState is the externally visible state of one submission.
type TaskState string

const (
	StateQueued    TaskState = "queued"
	StateScanning  TaskState = "scanning"
	StateClean     TaskState = "clean"
	StateInfected  TaskState = "infected"
	StateFailed    TaskState = "failed"
	StateCancelled TaskState = "cancelled"
	StateReleasing TaskState = "releasing"
	StateReleased  TaskState = "released"
)

// Err* values are returned by the public API. Release refusals other than
// ErrAlreadyReleased leave the file in quarantine.
var (
	ErrUnknownTenant   = errors.New("quarantine: unknown tenant")
	ErrBadDigest       = errors.New("quarantine: invalid digest")
	ErrBlobMissing     = errors.New("quarantine: frozen blob missing")
	ErrUnknownTask     = errors.New("quarantine: unknown task")
	ErrCancelled       = errors.New("quarantine: task cancelled")
	ErrNotReady        = errors.New("quarantine: result not committed yet")
	ErrNotClean        = errors.New("quarantine: result is not clean")
	ErrStaleResult     = errors.New("quarantine: result was produced by an old rule version")
	ErrTooLate         = errors.New("quarantine: task already committed")
	ErrReleaseInFlight = errors.New("quarantine: release already in progress")
	ErrBindingMismatch = errors.New("quarantine: result binding does not match its fields")
	ErrClosed          = errors.New("quarantine: engine closed")
	ErrInvalidState    = errors.New("quarantine: invalid persisted state")
)

// Result is a committed scan outcome. It is bound to the tenant, the content
// digest, the rule version that was frozen at submission time, and the task ID.
type Result struct {
	TaskID       TaskID      `json:"task_id"`
	Tenant       Tenant      `json:"tenant"`
	Digest       Digest      `json:"digest"`
	RuleVersion  RuleVersion `json:"rule_version"`
	Verdict      Verdict     `json:"verdict"`
	Reason       string      `json:"reason,omitempty"`
	JobID        string      `json:"job_id,omitempty"`
	Attempt      int         `json:"attempt,omitempty"`
	CommittedAt  time.Time   `json:"committed_at"`
	Released     bool        `json:"released"`
	ReleasePath  string      `json:"release_path,omitempty"`
	ReleaseError string      `json:"release_error,omitempty"`
	Binding      string      `json:"binding"`
}

// BindingFor computes the binding value that ties a result to its identity.
func BindingFor(taskID TaskID, tenant Tenant, digest Digest, rule RuleVersion) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d\x00%s\x00%s\x00%d", uint64(taskID), tenant, digest, int64(rule))
	return hex.EncodeToString(h.Sum(nil))
}

// Validate recomputes the binding and rejects a result whose identity fields
// were changed after it was committed.
func (r *Result) Validate() error {
	if r == nil {
		return ErrNotReady
	}
	if r.Binding != BindingFor(r.TaskID, r.Tenant, r.Digest, r.RuleVersion) {
		return ErrBindingMismatch
	}
	switch r.Verdict {
	case VerdictClean, VerdictInfected, VerdictError:
	default:
		return ErrBindingMismatch
	}
	return nil
}

// Clone returns a deep copy safe to hand to a caller.
func (r *Result) Clone() *Result {
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

// TaskView is a snapshot of one submission.
type TaskView struct {
	TaskID      TaskID      `json:"task_id"`
	Tenant      Tenant      `json:"tenant"`
	Digest      Digest      `json:"digest"`
	RuleVersion RuleVersion `json:"rule_version"`
	State       TaskState   `json:"state"`
	JobID       string      `json:"job_id,omitempty"`
	Attempts    int         `json:"attempts,omitempty"`
	Merged      bool        `json:"merged"`
	Reason      string      `json:"reason,omitempty"`
	Result      *Result     `json:"result,omitempty"`
}

// SubmitRoute describes how a submission was handled.
type SubmitRoute string

const (
	RouteNew       SubmitRoute = "new"
	RouteMerged    SubmitRoute = "merged"
	RouteCached    SubmitRoute = "cached"
	RouteDuplicate SubmitRoute = "duplicate"
)

// Submission is returned by Submit.
type Submission struct {
	TaskID TaskID      `json:"task_id"`
	State  TaskState   `json:"state"`
	Route  SubmitRoute `json:"route"`
	JobID  string      `json:"job_id"`
	Result *Result     `json:"result,omitempty"`
}

// ReleaseInfo is returned by Release.
type ReleaseInfo struct {
	TaskID      TaskID      `json:"task_id"`
	Tenant      Tenant      `json:"tenant"`
	Digest      Digest      `json:"digest"`
	RuleVersion RuleVersion `json:"rule_version"`
	Path        string      `json:"path"`
	Already     bool        `json:"already"`
}

// Stats is an instantaneous view used by tests and the CLI.
type Stats struct {
	Rule         RuleVersion `json:"rule"`
	Slots        int         `json:"slots"`
	Inflight     int         `json:"inflight"`
	MaxInflight  int         `json:"max_inflight"`
	ScannerCalls int         `json:"scanner_calls"`
	Dispatches   int         `json:"dispatches"`
	Tasks        int         `json:"tasks"`
	Jobs         int         `json:"jobs"`
	Queued       int         `json:"queued"`
}

// NormalizeDigest lower-cases and validates a digest.
func NormalizeDigest(s string) (Digest, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 64 {
		return "", ErrBadDigest
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", ErrBadDigest
	}
	return Digest(s), nil
}

// DigestBytes computes the digest of b.
func DigestBytes(b []byte) Digest {
	sum := sha256.Sum256(b)
	return Digest(hex.EncodeToString(sum[:]))
}
