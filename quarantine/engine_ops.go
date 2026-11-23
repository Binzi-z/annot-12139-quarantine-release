package quarantine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Submit freezes data under its SHA-256 and creates a task.
//
// If requestID is non-empty it is an idempotency key scoped to the tenant:
// resubmitting the same requestID with the same content returns the original
// task and its determined result; reusing it with different content fails with
// ErrRequestConflict.
//
// When a live job for the same tenant, digest and rule version exists, the new
// task attaches to that job instead of starting a second scan. Jobs are never
// shared across tenants. When a completed outcome exists for the same tenant,
// digest and rule version, a new task adopts it without another scanner call.
func (e *Engine) Submit(tenant Tenant, data []byte, requestID string) (Submission, error) {
	return e.SubmitContext(context.Background(), tenant, data, requestID)
}

// SubmitContext is Submit with a cancellation check. The engine's own work is
// performed synchronously; ctx only lets a caller abandon before enqueueing.
func (e *Engine) SubmitContext(ctx context.Context, tenant Tenant, data []byte, requestID string) (Submission, error) {
	if err := ctx.Err(); err != nil {
		return Submission{}, err
	}
	if err := validateTenant(tenant); err != nil {
		return Submission{}, err
	}
	if !e.tenantKnown(tenant) {
		return Submission{}, fmt.Errorf("%w: %q", ErrUnknownTenant, tenant)
	}
	d, err := e.store.WriteFrozenBlob(data)
	if err != nil {
		return Submission{}, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return Submission{}, ErrClosed
	}
	if requestID != "" {
		rk := requestKey(tenant, requestID)
		if id, ok := e.requests[rk]; ok {
			t := e.tasks[id]
			if t == nil || t.tenant != tenant {
				return Submission{}, ErrUnknownTask
			}
			if t.digest != d {
				return Submission{}, ErrRequestConflict
			}
			e.addEventLocked(Event{Kind: "duplicate", TaskID: t.id, Tenant: tenant, Digest: d, Rule: t.rule})
			return Submission{TaskID: t.id, State: t.state, Route: RouteDuplicate, JobID: t.jobID, Result: t.result.Clone()}, nil
		}
	}

	t := &task{
		id:        e.nextTask,
		tenant:    tenant,
		digest:    d,
		rule:      e.rule,
		state:     StateQueued,
		requestID: requestID,
	}
	e.nextTask++
	e.tasks[t.id] = t
	key := jobKey(tenant, d, e.rule)

	route := RouteNew
	if j := e.active[key]; j != nil {
		// Same tenant, same digest, same frozen rule: merge into the live job.
		j.tasks[t.id] = struct{}{}
		t.merged = true
		t.jobID = j.id
		t.state = StateScanning
		if j.state == jobQueued {
			t.state = StateQueued
		}
		e.addEventLocked(Event{Kind: "merge", TaskID: t.id, JobID: j.id, Tenant: tenant, Digest: d, Rule: e.rule, Detail: fmt.Sprintf("merged into job with %d task(s)", len(j.tasks))})
		route = RouteMerged
	} else if out, ok := e.cache[key]; ok {
		res := &Result{
			TaskID:      t.id,
			Tenant:      tenant,
			Digest:      d,
			RuleVersion: e.rule,
			Verdict:     out.verdict,
			Reason:      out.reason,
			CommittedAt: e.clock.Now(),
			Binding:     BindingFor(t.id, tenant, d, e.rule),
		}
		t.result = res
		t.state = stateForVerdict(out.verdict)
		t.reason = out.reason
		e.addEventLocked(Event{Kind: "cache_hit", TaskID: t.id, Tenant: tenant, Digest: d, Rule: e.rule})
		route = RouteCached
	} else {
		j := &job{
			id:     fmt.Sprintf("job-%d", e.nextJob),
			seq:    e.nextJob,
			tenant: tenant,
			digest: d,
			rule:   e.rule,
			state:  jobQueued,
			tasks:  map[TaskID]struct{}{t.id: {}},
			slot:   -1,
		}
		e.nextJob++
		e.jobs[j.id] = j
		e.active[key] = j
		t.jobID = j.id
		e.addEventLocked(Event{Kind: "enqueue", TaskID: t.id, JobID: j.id, Tenant: tenant, Digest: d, Rule: e.rule})
	}
	if requestID != "" {
		e.requests[requestKey(tenant, requestID)] = t.id
	}
	err = e.persistLocked()
	e.bumpLocked()
	return Submission{TaskID: t.id, State: t.state, Route: route, JobID: t.jobID, Result: t.result.Clone()}, err
}

// SubmitFile reads path and submits its bytes.
func (e *Engine) SubmitFile(tenant Tenant, path, requestID string) (Submission, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Submission{}, err
	}
	return e.Submit(tenant, b, requestID)
}

// Get returns a task snapshot. Tasks are visible only to their owning tenant;
// a task belonging to another tenant is reported as unknown.
func (e *Engine) Get(tenant Tenant, id TaskID) (TaskView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t := e.tasks[id]
	if t == nil || t.tenant != tenant {
		return TaskView{}, ErrUnknownTask
	}
	return e.taskViewLocked(t), nil
}

// GetByRequest returns the task created for a tenant request ID.
func (e *Engine) GetByRequest(tenant Tenant, requestID string) (TaskView, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	id, ok := e.requests[requestKey(tenant, requestID)]
	if !ok {
		return TaskView{}, ErrUnknownTask
	}
	t := e.tasks[id]
	if t == nil || t.tenant != tenant {
		return TaskView{}, ErrUnknownTask
	}
	return e.taskViewLocked(t), nil
}

// Tasks lists a tenant's tasks in submission order.
func (e *Engine) Tasks(tenant Tenant) []TaskView {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []TaskView
	for _, t := range e.sortedTasksLocked() {
		if t.tenant == tenant {
			out = append(out, e.taskViewLocked(t))
		}
	}
	return out
}

// Result returns the committed result for a task.
func (e *Engine) Result(tenant Tenant, id TaskID) (*Result, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	t := e.tasks[id]
	if t == nil || t.tenant != tenant {
		return nil, ErrUnknownTask
	}
	if t.result == nil {
		if t.state == StateCancelled {
			return nil, ErrCancelled
		}
		return nil, ErrNotReady
	}
	r := t.result.Clone()
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// Wait blocks until the task reaches a terminal state or ctx ends.
func (e *Engine) Wait(ctx context.Context, tenant Tenant, id TaskID) (TaskView, error) {
	for {
		e.mu.Lock()
		t := e.tasks[id]
		if t == nil || t.tenant != tenant {
			e.mu.Unlock()
			return TaskView{}, ErrUnknownTask
		}
		done := e.terminalLocked(t)
		v := e.taskViewLocked(t)
		ch := e.notify
		e.mu.Unlock()
		if done {
			return v, nil
		}
		select {
		case <-ctx.Done():
			return v, ctx.Err()
		case <-ch:
		case <-e.stop:
			return v, ErrClosed
		}
	}
}

// WaitAll waits until every task of the tenant is terminal, the engine closes,
// or ctx ends.
func (e *Engine) WaitAll(ctx context.Context, tenant Tenant) ([]TaskView, error) {
	for {
		e.mu.Lock()
		all := true
		var views []TaskView
		for _, t := range e.sortedTasksLocked() {
			if t.tenant != tenant {
				continue
			}
			views = append(views, e.taskViewLocked(t))
			if !e.terminalLocked(t) {
				all = false
			}
		}
		ch := e.notify
		e.mu.Unlock()
		if all {
			return views, nil
		}
		select {
		case <-ctx.Done():
			return views, ctx.Err()
		case <-ch:
		case <-e.stop:
			return views, ErrClosed
		}
	}
}

// Cancel commits cancellation for a task that has not yet had a result
// committed. Cancelling a task whose result is already committed is too late.
// Cancelling a merged task detaches only that task; the shared job continues
// for the remaining tasks, and if it was already scanning, the slot is
// returned immediately while the abandoned scan's response is discarded.
func (e *Engine) Cancel(tenant Tenant, id TaskID) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return ErrClosed
	}
	t := e.tasks[id]
	if t == nil || t.tenant != tenant {
		return ErrUnknownTask
	}
	if e.terminalLocked(t) || t.result != nil {
		return ErrTooLate
	}
	if t.state != StateQueued && t.state != StateScanning {
		return ErrTooLate
	}
	j := e.jobs[t.jobID]
	if j != nil {
		delete(j.tasks, id)
		if len(j.tasks) == 0 {
			e.cancelJobLocked(j, "cancelled by tenant "+string(tenant))
		}
	}
	t.state = StateCancelled
	t.reason = "cancelled before the scan result committed"
	e.addEventLocked(Event{Kind: "cancel", TaskID: id, JobID: t.jobID, Tenant: tenant, Detail: t.reason})
	err := e.persistLocked()
	e.bumpLocked()
	return err
}

func (e *Engine) cancelJobLocked(j *job, reason string) {
	if j.state == jobSettled || j.state == jobFailed || j.state == jobCancelled {
		return
	}
	if j.cancel != nil {
		j.cancel() // the worker returns promptly and frees its slot
		j.cancel = nil
	}
	j.state = jobCancelled
	j.reason = reason
	e.dropActiveLocked(j)
	e.addEventLocked(Event{Kind: "job_cancelled", JobID: j.id, Tenant: j.tenant, Digest: j.digest, Rule: j.rule, Detail: reason})
	delete(e.jobs, j.id)
}

func (e *Engine) dropActiveLocked(j *job) {
	key := jobKey(j.tenant, j.digest, j.rule)
	if e.active[key] == j {
		delete(e.active, key)
	}
}

// Release publishes a clean result to the release directory.
//
// The commit point is taken under the engine lock: the task must hold a clean,
// bound result whose RuleVersion equals the current rule version, and it must
// not already be releasing. Once committed, the copy proceeds even if the rule
// is updated concurrently; the result's rule version also identifies what was
// released. A rule update that commits first makes this release stale.
func (e *Engine) Release(tenant Tenant, id TaskID) (ReleaseInfo, error) {
	if h := e.cfg.Hooks; h != nil && h.BeforeReleaseCommit != nil {
		h.BeforeReleaseCommit(id)
	}

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return ReleaseInfo{}, ErrClosed
	}
	t := e.tasks[id]
	if t == nil || t.tenant != tenant {
		e.mu.Unlock()
		return ReleaseInfo{}, ErrUnknownTask
	}
	if t.state == StateReleased && t.result != nil && t.result.Released {
		info := ReleaseInfo{TaskID: id, Tenant: tenant, Digest: t.digest, RuleVersion: t.result.RuleVersion, Path: t.result.ReleasePath, Already: true}
		e.mu.Unlock()
		return info, nil
	}
	if t.state == StateReleasing {
		e.mu.Unlock()
		return ReleaseInfo{}, ErrReleaseInFlight
	}
	if t.result == nil {
		e.mu.Unlock()
		switch t.state {
		case StateCancelled:
			return ReleaseInfo{}, ErrCancelled
		case StateFailed:
			return ReleaseInfo{}, fmt.Errorf("%w: scan did not succeed", ErrNotClean)
		default:
			return ReleaseInfo{}, ErrNotReady
		}
	}
	if err := t.result.Validate(); err != nil {
		e.mu.Unlock()
		return ReleaseInfo{}, err
	}
	if t.result.Verdict != VerdictClean {
		e.mu.Unlock()
		return ReleaseInfo{}, fmt.Errorf("%w: verdict %s", ErrNotClean, t.result.Verdict)
	}
	if t.result.RuleVersion != e.rule {
		e.mu.Unlock()
		return ReleaseInfo{}, fmt.Errorf("%w: result rule %d, current rule %d", ErrStaleResult, t.result.RuleVersion, e.rule)
	}

	// Commit point: the release is claimed and the result is marked released
	// while the rule still matches.
	t.state = StateReleasing
	t.result.Released = true
	t.result.ReleasePath = e.releaseTarget(t)
	t.result.ReleaseError = ""
	e.addEventLocked(Event{Kind: "release_commit", TaskID: id, Tenant: tenant, Digest: t.digest, Rule: t.result.RuleVersion})
	persistErr := e.persistLocked()
	e.bumpLocked()
	target := t.result.ReleasePath
	rule := t.result.RuleVersion
	digest := t.digest
	e.mu.Unlock()

	if persistErr != nil {
		// Roll back the claim; nothing was copied yet.
		e.mu.Lock()
		if tt := e.tasks[id]; tt != nil && tt.state == StateReleasing {
			tt.state = StateClean
			if tt.result != nil {
				tt.result.Released = false
				tt.result.ReleasePath = ""
			}
		}
		e.bumpLocked()
		e.mu.Unlock()
		return ReleaseInfo{}, persistErr
	}

	if h := e.cfg.Hooks; h != nil && h.AfterReleaseCommit != nil {
		h.AfterReleaseCommit(id)
	}

	cerr := e.copyRelease(digest, target)

	e.mu.Lock()
	defer e.mu.Unlock()
	t = e.tasks[id]
	if t == nil {
		return ReleaseInfo{}, ErrUnknownTask
	}
	if cerr != nil {
		t.state = StateClean
		if t.result != nil {
			t.result.Released = false
			t.result.ReleasePath = ""
			t.result.ReleaseError = cerr.Error()
		}
		e.addEventLocked(Event{Kind: "release_failed", TaskID: id, Tenant: tenant, Digest: digest, Detail: cerr.Error()})
		_ = e.persistLocked()
		e.bumpLocked()
		return ReleaseInfo{}, fmt.Errorf("quarantine: release copy failed: %w", cerr)
	}
	t.state = StateReleased
	if t.result != nil {
		t.result.Released = true
		t.result.ReleasePath = target
		t.result.ReleaseError = ""
	}
	e.addEventLocked(Event{Kind: "released", TaskID: id, Tenant: tenant, Digest: digest, Rule: rule, Detail: target})
	err := e.persistLocked()
	e.bumpLocked()
	return ReleaseInfo{TaskID: id, Tenant: tenant, Digest: digest, RuleVersion: rule, Path: target}, err
}

func (e *Engine) releaseTarget(t *task) string {
	return filepath.Join(e.store.ReleaseDir(), fmt.Sprintf("%s-%s-t%d.bin", sanitize(string(t.tenant)), string(t.digest)[:16], t.id))
}

// copyRelease copies the frozen blob to dst and verifies the written digest, so
// the release directory's actual bytes prove what was released.
func (e *Engine) copyRelease(d Digest, dst string) error {
	data, _, err := e.store.FrozenBlob(d)
	if err != nil {
		return err
	}
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".release-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if got := fileDigest(tmpName); got != d {
		return fmt.Errorf("release temp digest mismatch: got %s want %s", got, d)
	}
	if existing, rerr := os.ReadFile(dst); rerr == nil {
		if DigestBytes(existing) == d {
			return nil
		}
		if rmErr := os.Remove(dst); rmErr != nil {
			return fmt.Errorf("remove stale release target: %w", rmErr)
		}
	}
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	if got := fileDigest(dst); got != d {
		os.Remove(dst)
		return fmt.Errorf("released file digest mismatch: got %s want %s", got, d)
	}
	return nil
}

func fileDigest(path string) Digest {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return DigestBytes(b)
}

func sanitize(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// ---- scheduler ----

func (e *Engine) schedulerLoop() {
	defer e.schedulerWG.Done()
	for {
		e.mu.Lock()
		if e.closed {
			e.mu.Unlock()
			return
		}
		e.dispatchLocked()
		ch := e.notify
		// If a job is waiting out a retry backoff, arm a timer so it is
		// re-dispatched when the backoff elapses rather than only on the next
		// unrelated state change.
		var backoff <-chan time.Time
		if d := e.nextBackoffLocked(); d > 0 {
			backoff = e.clock.After(d)
		}
		e.mu.Unlock()
		select {
		case <-e.stop:
			return
		case <-ch:
		case <-backoff:
		}
	}
}

// nextBackoffLocked returns the shortest remaining retry delay among queued
// jobs, or 0 if none is waiting.
func (e *Engine) nextBackoffLocked() time.Duration {
	now := e.clock.Now()
	var best time.Duration
	for _, j := range e.jobs {
		if j.state != jobQueued || !now.Before(j.notBefore) {
			continue
		}
		d := j.notBefore.Sub(now)
		if best == 0 || d < best {
			best = d
		}
	}
	return best
}

// dispatchLocked hands queued work to free slots. When more than one tenant is
// waiting, each tenant may hold at most Slots-1 slots so a tenant flooding or
// cancelling requests cannot monopolize the pool. Selection is round-robin
// across tenants and then by submission order.
func (e *Engine) dispatchLocked() {
	for e.inflight < e.cfg.Slots {
		j := e.pickJobLocked()
		if j == nil {
			return
		}
		slot := e.firstFreeSlotLocked()
		if slot < 0 {
			return
		}
		j.attempt++
		j.state = jobScanning
		j.inflightAttempt = j.attempt
		j.slot = slot
		j.reason = ""
		e.inflight++
		e.tenantInflight[j.tenant]++
		e.usedSlot[slot] = true
		e.slotJob[slot] = j
		if e.inflight > e.maxInflight {
			e.maxInflight = e.inflight
		}
		e.dispatches++
		for id := range j.tasks {
			if t := e.tasks[id]; t != nil {
				t.state = StateScanning
				t.attempts = j.attempt
				t.reason = ""
			}
		}
		e.addEventLocked(Event{Kind: "dispatch", JobID: j.id, Tenant: j.tenant, Digest: j.digest, Rule: j.rule, Attempt: j.attempt, Slot: slot})
		e.rr++
		e.wg.Add(1)
		att := j.attempt
		go e.runAttempt(j, slot, att)
	}
}

// pickJobLocked selects the next job. It prefers a tenant below its share,
// rotating the starting tenant each round; if every waiting tenant is at its
// share it picks the least-loaded tenant so slots are never left idle while
// work exists.
func (e *Engine) pickJobLocked() *job {
	now := e.clock.Now()
	var queued []*job
	waiting := map[Tenant]bool{}
	for _, j := range e.jobs {
		if j.state != jobQueued || now.Before(j.notBefore) {
			continue
		}
		queued = append(queued, j)
		waiting[j.tenant] = true
	}
	if len(queued) == 0 {
		return nil
	}
	var tenants []Tenant
	for _, t := range e.cfg.Tenants {
		if waiting[t] {
			tenants = append(tenants, t)
		}
	}
	capPerTenant := e.cfg.Slots
	if len(tenants) > 1 {
		capPerTenant = e.cfg.Slots - 1
		if capPerTenant < 1 {
			capPerTenant = 1
		}
	}
	earliest := func(t Tenant) *job {
		var best *job
		for _, j := range queued {
			if j.tenant != t {
				continue
			}
			if best == nil || j.seq < best.seq {
				best = j
			}
		}
		return best
	}
	for i := 0; i < len(tenants); i++ {
		t := tenants[(int(e.rr)+i)%len(tenants)]
		if e.tenantInflight[t] >= capPerTenant {
			continue
		}
		if j := earliest(t); j != nil {
			return j
		}
	}
	// Every waiting tenant is at its share: let the least-loaded one run so
	// no slot is wasted. Fairness still holds because the rotation advances.
	var best *job
	bestLoad := int(^uint(0) >> 1)
	for _, j := range queued {
		load := e.tenantInflight[j.tenant]
		if load < bestLoad || (load == bestLoad && best != nil && j.seq < best.seq) {
			best = j
			bestLoad = load
		}
	}
	return best
}

// runAttempt performs one scanner call for a job and either commits the
// result, schedules a bounded retry, or fails the job.
//
// A worker slot is owned by exactly one physical scanner call and is released
// only when that call returns. Cancellation and timeout commit their decision
// under the lock and cancel ctx immediately; the shipped Simulator honors ctx
// and returns promptly, so the slot is returned in bounded time. The response
// of an attempt that lost authority is discarded, never committed.
func (e *Engine) runAttempt(j *job, slot, attempt int) {
	defer e.wg.Done()

	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	if e.closed || j.state != jobScanning || j.inflightAttempt != attempt || j.slot != slot {
		e.mu.Unlock()
		cancel()
		e.freeStandbySlot(j, slot)
		return
	}
	j.cancel = cancel
	e.scannerCalls++
	req := ScanRequest{
		JobID:   j.id,
		Tenant:  j.tenant,
		Digest:  j.digest,
		Rule:    j.rule,
		Attempt: attempt,
		Path:    e.scanPath(j.digest),
	}
	e.mu.Unlock()

	var timer <-chan time.Time
	if e.cfg.AttemptTimeout > 0 {
		timer = e.clock.After(e.cfg.AttemptTimeout)
	}
	ch := make(chan answer, 1)
	go func() {
		out, err := e.scan.Scan(ctx, req)
		ch <- answer{out: out, err: err}
	}()
	var res answer
	timedOut := false
	select {
	case res = <-ch:
	case <-timer:
		timedOut = true
		cancel()
	}
	cancel()

	e.mu.Lock()
	defer e.mu.Unlock()
	defer e.bumpLocked()
	defer func() { _ = e.persistLocked() }()
	e.freeSlotLocked(j, slot)

	if e.closed {
		return
	}
	if timedOut {
		// The attempt timed out. Release the slot without waiting on the
		// scanner, so a scanner that ignores cancellation cannot pin a worker.
		// Any response it eventually produces is drained and discarded.
		e.addEventLocked(Event{Kind: "discard_late", JobID: j.id, Tenant: j.tenant, Digest: j.digest, Rule: j.rule, Attempt: attempt, Detail: "timed out"})
		if j.state == jobScanning && j.inflightAttempt == attempt {
			j.cancel = nil
			e.attemptFailedLocked(j, attempt, fmt.Sprintf("scan attempt %d timed out after %s", attempt, e.cfg.AttemptTimeout))
		}
		go func() {
			<-ch // drain; never touches engine state
		}()
		return
	}
	if j.state != jobScanning || j.inflightAttempt != attempt {
		// Cancelled (or superseded) while the scanner ran. The response has no
		// authority to commit and is discarded at this commit point.
		e.addEventLocked(Event{Kind: "discard_late", JobID: j.id, Tenant: j.tenant, Digest: j.digest, Rule: j.rule, Attempt: attempt, Detail: "attempt lost authority"})
		return
	}
	j.cancel = nil

	if res.err == nil && (res.out.Verdict == VerdictClean || res.out.Verdict == VerdictInfected) {
		e.commitResultLocked(j, res.out, e.clock.Now())
		return
	}
	reason := "scan failed"
	if res.err != nil {
		reason = "scan failed: " + res.err.Error()
	} else {
		reason = "scan returned invalid verdict " + string(res.out.Verdict)
	}
	e.attemptFailedLocked(j, attempt, reason)
}

// freeStandbySlot releases a slot for a worker that never started (its job was
// already cancelled between dispatch and goroutine scheduling).
func (e *Engine) freeStandbySlot(j *job, slot int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.freeSlotLocked(j, slot)
	e.bumpLocked()
	_ = e.persistLocked()
}

// answer is the scanner's reply.
type answer struct {
	out ScanOutput
	err error
}

// attemptFailedLocked records a failed attempt and either requeues the job or
// commits a bound error result when the retry bound is exhausted. A committed
// error result is sticky for the same tenant/digest/rule: repeated requests
// adopt it instead of retrying without bound, and it can never be released.
func (e *Engine) attemptFailedLocked(j *job, attempt int, reason string) {
	e.addEventLocked(Event{Kind: "attempt_failed", JobID: j.id, Tenant: j.tenant, Digest: j.digest, Rule: j.rule, Attempt: attempt, Detail: reason})
	if attempt >= e.cfg.MaxAttempts {
		e.failJobLocked(j, fmt.Sprintf("%s (attempts exhausted after %d)", reason, attempt))
		return
	}
	j.state = jobQueued
	j.reason = reason
	if e.cfg.RetryBackoff > 0 {
		j.notBefore = e.clock.Now().Add(e.cfg.RetryBackoff)
	}
	for id := range j.tasks {
		if t := e.tasks[id]; t != nil && t.state != StateCancelled {
			t.state = StateQueued
			t.reason = reason
		}
	}
}

// freeSlotLocked frees the job's worker slot. If the job already holds no
// slot this is a no-op, so cancellation and worker completion can both call it.
func (e *Engine) freeSlotLocked(j *job, slot int) {
	if slot < 0 || slot >= len(e.usedSlot) || !e.usedSlot[slot] {
		return
	}
	if e.slotJob[slot] != j {
		// The slot belongs to a different job; never free someone else's slot.
		return
	}
	e.usedSlot[slot] = false
	e.slotJob[slot] = nil
	if e.inflight > 0 {
		e.inflight--
	}
	if e.tenantInflight[j.tenant] > 0 {
		e.tenantInflight[j.tenant]--
	}
	if j.slot == slot {
		j.slot = -1
	}
}

func (e *Engine) commitResultLocked(j *job, out ScanOutput, now time.Time) {
	j.state = jobSettled
	j.reason = out.Reason
	e.dropActiveLocked(j)
	e.cache[jobKey(j.tenant, j.digest, j.rule)] = cachedOutcome{verdict: out.Verdict, reason: out.Reason}
	ids := make([]TaskID, 0, len(j.tasks))
	for id := range j.tasks {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, k int) bool { return ids[i] < ids[k] })
	for _, id := range ids {
		t := e.tasks[id]
		if t == nil || t.state == StateCancelled {
			continue
		}
		res := &Result{
			TaskID:      t.id,
			Tenant:      t.tenant,
			Digest:      t.digest,
			RuleVersion: j.rule,
			Verdict:     out.Verdict,
			Reason:      out.Reason,
			JobID:       j.id,
			Attempt:     j.attempt,
			CommittedAt: now,
			Binding:     BindingFor(t.id, t.tenant, t.digest, j.rule),
		}
		t.result = res
		t.state = stateForVerdict(out.Verdict)
		t.reason = out.Reason
		t.attempts = j.attempt
	}
	e.addEventLocked(Event{Kind: "result_committed", JobID: j.id, Tenant: j.tenant, Digest: j.digest, Rule: j.rule, Attempt: j.attempt, Detail: string(out.Verdict)})
	delete(e.jobs, j.id)
}

// failJobLocked terminals a job whose attempts are exhausted. It commits a
// bound error result to every attached task, caches it for the rule version,
// and drops the active entry. The file therefore remains in quarantine and can
// never be released, while repeated requests get the same determined outcome.
func (e *Engine) failJobLocked(j *job, reason string) {
	j.state = jobFailed
	j.reason = reason
	e.dropActiveLocked(j)
	e.cache[jobKey(j.tenant, j.digest, j.rule)] = cachedOutcome{verdict: VerdictError, reason: reason}
	ids := make([]TaskID, 0, len(j.tasks))
	for id := range j.tasks {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, k int) bool { return ids[i] < ids[k] })
	for _, id := range ids {
		t := e.tasks[id]
		if t == nil || t.state == StateCancelled {
			continue
		}
		res := &Result{
			TaskID:      t.id,
			Tenant:      t.tenant,
			Digest:      t.digest,
			RuleVersion: j.rule,
			Verdict:     VerdictError,
			Reason:      reason,
			JobID:       j.id,
			Attempt:     j.attempt,
			CommittedAt: e.clock.Now(),
			Binding:     BindingFor(t.id, t.tenant, t.digest, j.rule),
		}
		t.result = res
		t.state = StateFailed
		t.reason = reason
		t.attempts = j.attempt
	}
	e.addEventLocked(Event{Kind: "job_failed", JobID: j.id, Tenant: j.tenant, Digest: j.digest, Rule: j.rule, Attempt: j.attempt, Detail: reason})
	delete(e.jobs, j.id)
}

// QueueDepth reports queued jobs for a tenant.
func (e *Engine) QueueDepth(tenant Tenant) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, j := range e.jobs {
		if j.tenant == tenant && j.state == jobQueued {
			n++
		}
	}
	return n
}

// InflightByTenant reports active slots per tenant.
func (e *Engine) InflightByTenant() map[Tenant]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[Tenant]int, len(e.tenantInflight))
	for k, v := range e.tenantInflight {
		out[k] = v
	}
	return out
}

// ScannerCalls reports the number of scanner invocations started.
func (e *Engine) ScannerCalls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.scannerCalls
}

// DispatchSequence returns the ordered dispatch events.
func (e *Engine) DispatchSequence() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Event
	for _, ev := range e.events {
		if ev.Kind == "dispatch" {
			out = append(out, ev)
		}
	}
	return out
}

// SeedResult inserts a committed result directly. It exists for the offline
// demo and the model comparison; normal code should use Submit.
func (e *Engine) SeedResult(tenant Tenant, data []byte, verdict Verdict, rule RuleVersion) (TaskID, error) {
	if err := validateTenant(tenant); err != nil {
		return 0, err
	}
	if !e.tenantKnown(tenant) {
		return 0, fmt.Errorf("%w: %q", ErrUnknownTenant, tenant)
	}
	if verdict != VerdictClean && verdict != VerdictInfected {
		return 0, errors.New("quarantine: seed verdict must be clean or infected")
	}
	d, err := e.store.WriteFrozenBlob(data)
	if err != nil {
		return 0, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return 0, ErrClosed
	}
	if rule <= 0 {
		rule = e.rule
	}
	id := e.nextTask
	e.nextTask++
	t := &task{id: id, tenant: tenant, digest: d, rule: rule, state: stateForVerdict(verdict), attempts: 1, reason: "seeded"}
	t.result = &Result{
		TaskID:      id,
		Tenant:      tenant,
		Digest:      d,
		RuleVersion: rule,
		Verdict:     verdict,
		Reason:      "seeded",
		CommittedAt: e.clock.Now(),
		Binding:     BindingFor(id, tenant, d, rule),
	}
	e.tasks[id] = t
	return id, e.persistLocked()
}
