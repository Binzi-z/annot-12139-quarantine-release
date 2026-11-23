package quarantine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Config configures an Engine. Zero values receive safe defaults, so the
// smallest useful configuration is Config{DataDir: dir}.
type Config struct {
	// DataDir holds the immutable quarantine blobs, the release directory and
	// the persisted result index. When empty a temporary directory is created
	// and removed on Close.
	DataDir string
	// Slots is the number of parallel scan workers. Default 3.
	Slots int
	// Tenants is the closed set of tenants allowed to use the engine.
	// Default {"tenant-a", "tenant-b"}.
	Tenants []Tenant
	// MaxAttempts bounds retries per scan job. Default 3.
	MaxAttempts int
	// AttemptTimeout bounds one scanner call. Default 10s. A value <= 0
	// disables the per-attempt timeout (not recommended).
	AttemptTimeout time.Duration
	// RetryBackoff delays a retry after a failed attempt. Default 0.
	RetryBackoff time.Duration
	// Clock drives timeouts and retry backoff. Default SystemClock.
	Clock Clock
	// Scanner is the scan backend. Default is the shipped Simulator.
	Scanner Scanner
	// UseFileLock serializes separate processes (the CLI) that share DataDir.
	UseFileLock bool
	// Hooks lets a test straddle the release commit point. Nil in normal use.
	Hooks *TestHooks
}

type testHooks = TestHooks

type jobState string

const (
	jobQueued    jobState = "queued"
	jobScanning  jobState = "scanning"
	jobSettled   jobState = "settled"
	jobFailed    jobState = "failed"
	jobCancelled jobState = "cancelled"
)

type task struct {
	id        TaskID
	tenant    Tenant
	digest    Digest
	rule      RuleVersion
	jobID     string
	state     TaskState
	attempts  int
	merged    bool
	requestID string
	reason    string
	result    *Result
}

type job struct {
	id              string
	seq             uint64
	tenant          Tenant
	digest          Digest
	rule            RuleVersion
	state           jobState
	tasks           map[TaskID]struct{}
	attempt         int
	inflightAttempt int
	slot            int
	notBefore       time.Time
	cancel          context.CancelFunc
	reason          string
}

type cachedOutcome struct {
	verdict Verdict
	reason  string
}

// Event is one entry in the engine's in-memory audit trail. Tests use it to
// check dispatch order, slot usage and scanner call counts.
type Event struct {
	Kind    string      `json:"kind"`
	At      time.Time   `json:"at"`
	JobID   string      `json:"job_id,omitempty"`
	TaskID  TaskID      `json:"task_id,omitempty"`
	Tenant  Tenant      `json:"tenant,omitempty"`
	Digest  Digest      `json:"digest,omitempty"`
	Rule    RuleVersion `json:"rule,omitempty"`
	Attempt int         `json:"attempt,omitempty"`
	Slot    int         `json:"slot,omitempty"`
	Detail  string      `json:"detail,omitempty"`
}

// Engine is safe for concurrent use.
type Engine struct {
	cfg   Config
	store *Store
	clock Clock
	scan  Scanner

	mu             sync.Mutex
	notify         chan struct{}
	closed         bool
	rule           RuleVersion
	tasks          map[TaskID]*task
	jobs           map[string]*job
	active         map[string]*job // key -> live job
	cache          map[string]cachedOutcome
	requests       map[string]TaskID
	nextTask       TaskID
	nextJob        uint64
	rr             int
	inflight       int
	tenantInflight map[Tenant]int
	usedSlot       []bool
	slotJob        []*job
	scannerCalls   int
	dispatches     int
	maxInflight    int
	events         []Event
	lastPersistErr error

	wg          sync.WaitGroup
	stop        chan struct{}
	schedulerWG sync.WaitGroup

	autoDir bool
}

// NewEngine loads (or creates) the persistent state and starts the scheduler.
func NewEngine(cfg Config) (*Engine, error) {
	if cfg.Slots <= 0 {
		cfg.Slots = 3
	}
	if cfg.Slots > 64 {
		return nil, fmt.Errorf("quarantine: slots must be <= 64")
	}
	if len(cfg.Tenants) == 0 {
		cfg.Tenants = []Tenant{"tenant-a", "tenant-b"}
	}
	seen := map[Tenant]bool{}
	for _, t := range cfg.Tenants {
		if err := validateTenant(t); err != nil {
			return nil, err
		}
		if seen[t] {
			return nil, fmt.Errorf("quarantine: duplicate tenant %q", t)
		}
		seen[t] = true
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.AttemptTimeout == 0 {
		cfg.AttemptTimeout = 10 * time.Second
	}
	if cfg.Clock == nil {
		cfg.Clock = SystemClock{}
	}
	if cfg.Scanner == nil {
		cfg.Scanner = NewSimulator(cfg.Clock, SimulatorOptions{})
	}

	autoDir := false
	dataDir := cfg.DataDir
	if dataDir == "" {
		d, err := os.MkdirTemp("", "quarantine-engine-*")
		if err != nil {
			return nil, err
		}
		dataDir = d
		autoDir = true
	}
	store, err := NewStore(dataDir, cfg.UseFileLock)
	if err != nil {
		if autoDir {
			os.RemoveAll(dataDir)
		}
		return nil, err
	}

	e := &Engine{
		cfg:            cfg,
		store:          store,
		clock:          cfg.Clock,
		scan:           cfg.Scanner,
		notify:         make(chan struct{}),
		rule:           1,
		tasks:          make(map[TaskID]*task),
		jobs:           make(map[string]*job),
		active:         make(map[string]*job),
		cache:          make(map[string]cachedOutcome),
		requests:       make(map[string]TaskID),
		nextTask:       1,
		nextJob:        1,
		tenantInflight: make(map[Tenant]int),
		usedSlot:       make([]bool, cfg.Slots),
		slotJob:        make([]*job, cfg.Slots),
		stop:           make(chan struct{}),
		autoDir:        autoDir,
	}
	if err := e.loadLocked(); err != nil {
		store.Close()
		if autoDir {
			os.RemoveAll(dataDir)
		}
		return nil, err
	}

	e.schedulerWG.Add(1)
	go e.schedulerLoop()
	return e, nil
}

func validateTenant(t Tenant) error {
	if t == "" {
		return ErrUnknownTenant
	}
	for _, r := range string(t) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("%w: illegal character %q", ErrUnknownTenant, r)
		}
	}
	return nil
}

// Dir returns the data directory.
func (e *Engine) Dir() string { return e.store.Dir() }

// ReleaseDir returns the directory into which clean files are published.
func (e *Engine) ReleaseDir() string { return e.store.ReleaseDir() }

// Rule returns the current scan rule version.
func (e *Engine) Rule() RuleVersion {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.rule
}

// UpdateRules commits a new rule version. Results committed under earlier rule
// versions remain queryable but can no longer be released.
func (e *Engine) UpdateRules() (RuleVersion, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return e.rule, ErrClosed
	}
	e.rule++
	e.addEventLocked(Event{Kind: "rule_update", At: e.clock.Now(), Rule: e.rule, Detail: fmt.Sprintf("rule advanced to %d", e.rule)})
	e.bumpLocked()
	err := e.persistLocked()
	return e.rule, err
}

// Close stops the scheduler, cancels in-flight scans, waits for workers and
// persists the final state.
func (e *Engine) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	close(e.stop)
	var cancels []context.CancelFunc
	for _, j := range e.jobs {
		if j.state == jobScanning && j.cancel != nil {
			cancels = append(cancels, j.cancel)
		}
	}
	e.bumpLocked()
	e.mu.Unlock()

	for _, c := range cancels {
		c()
	}
	e.schedulerWG.Wait()
	e.wg.Wait()

	e.mu.Lock()
	for _, j := range e.jobs {
		if j.state == jobQueued || j.state == jobScanning {
			e.failJobLocked(j, "engine closed before the scan committed")
		}
	}
	err := e.persistLocked()
	e.mu.Unlock()

	e.store.Close()
	if e.autoDir {
		os.RemoveAll(e.store.Dir())
	}
	return err
}

func (e *Engine) bumpLocked() {
	close(e.notify)
	e.notify = make(chan struct{})
}

func (e *Engine) addEventLocked(ev Event) {
	if ev.At.IsZero() {
		ev.At = e.clock.Now()
	}
	e.events = append(e.events, ev)
	// Bound the audit trail so a tenant that submits and cancels forever
	// cannot grow memory without limit. Older entries are dropped first.
	const maxEvents = 20000
	if len(e.events) > maxEvents {
		drop := len(e.events) - maxEvents
		e.events = append(e.events[:0], e.events[drop:]...)
	}
}

// Events returns a copy of the audit trail.
func (e *Engine) Events() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Event, len(e.events))
	copy(out, e.events)
	return out
}

// EventsOfKind returns the audit events of a given kind.
func (e *Engine) EventsOfKind(kind string) []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Event
	for _, ev := range e.events {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

// Stats returns an instantaneous snapshot.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Stats{
		Rule:         e.rule,
		Slots:        e.cfg.Slots,
		Inflight:     e.inflight,
		MaxInflight:  e.maxInflight,
		ScannerCalls: e.scannerCalls,
		Dispatches:   e.dispatches,
		Tasks:        len(e.tasks),
		Jobs:         len(e.jobs),
	}
	for _, j := range e.jobs {
		if j.state == jobQueued {
			st.Queued++
		}
	}
	return st
}

func (e *Engine) tenantKnown(t Tenant) bool {
	for _, x := range e.cfg.Tenants {
		if x == t {
			return true
		}
	}
	return false
}

func jobKey(t Tenant, d Digest, r RuleVersion) string {
	return fmt.Sprintf("%s|%s|%d", t, d, int64(r))
}

func (e *Engine) terminalLocked(t *task) bool {
	if t.result != nil && t.result.Released && t.state != StateReleased {
		return true
	}
	switch t.state {
	case StateClean, StateInfected, StateFailed, StateCancelled, StateReleased:
		return true
	}
	return false
}

func stateForVerdict(v Verdict) TaskState {
	switch v {
	case VerdictClean:
		return StateClean
	case VerdictInfected:
		return StateInfected
	default:
		return StateFailed
	}
}

func (e *Engine) taskViewLocked(t *task) TaskView {
	v := TaskView{
		TaskID:      t.id,
		Tenant:      t.tenant,
		Digest:      t.digest,
		RuleVersion: t.rule,
		State:       t.state,
		JobID:       t.jobID,
		Attempts:    t.attempts,
		Merged:      t.merged,
		Reason:      t.reason,
	}
	if t.result != nil {
		v.Result = t.result.Clone()
	}
	return v
}

func (e *Engine) sortedTasksLocked() []*task {
	out := make([]*task, 0, len(e.tasks))
	for _, t := range e.tasks {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

func (e *Engine) jobTaskIDs(j *job) []TaskID {
	ids := make([]TaskID, 0, len(j.tasks))
	for id := range j.tasks {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, k int) bool { return ids[i] < ids[k] })
	return ids
}

// firstFreeSlotLocked returns the lowest free worker slot index.
func (e *Engine) firstFreeSlotLocked() int {
	for i, used := range e.usedSlot {
		if !used {
			return i
		}
	}
	return -1
}

func (e *Engine) persistLocked() error {
	if e.store == nil {
		return nil
	}
	st := diskState{
		Version:  diskVersion,
		Rule:     e.rule,
		NextTask: e.nextTask,
		NextJob:  e.nextJob,
		Requests: make(map[string]TaskID, len(e.requests)),
	}
	for k, v := range e.requests {
		st.Requests[k] = v
	}
	for _, t := range e.sortedTasksLocked() {
		dt := &diskTask{
			ID:        t.id,
			Tenant:    t.tenant,
			Digest:    t.digest,
			Rule:      t.rule,
			JobID:     t.jobID,
			State:     t.state,
			Attempts:  t.attempts,
			Merged:    t.merged,
			RequestID: t.requestID,
			Reason:    t.reason,
			Result:    t.result,
		}
		st.Tasks = append(st.Tasks, dt)
	}
	err := e.store.Save(st)
	if err != nil {
		e.lastPersistErr = err
	}
	return err
}

const diskVersion = 1

type diskTask struct {
	ID        TaskID      `json:"id"`
	Tenant    Tenant      `json:"tenant"`
	Digest    Digest      `json:"digest"`
	Rule      RuleVersion `json:"rule"`
	JobID     string      `json:"job_id,omitempty"`
	State     TaskState   `json:"state"`
	Attempts  int         `json:"attempts,omitempty"`
	Merged    bool        `json:"merged,omitempty"`
	RequestID string      `json:"request_id,omitempty"`
	Reason    string      `json:"reason,omitempty"`
	Result    *Result     `json:"result,omitempty"`
}

type diskState struct {
	Version  int               `json:"version"`
	Rule     RuleVersion       `json:"rule"`
	NextTask TaskID            `json:"next_task"`
	NextJob  uint64            `json:"next_job"`
	Tasks    []*diskTask       `json:"tasks"`
	Requests map[string]TaskID `json:"requests,omitempty"`
}

func (e *Engine) loadLocked() error {
	st, ok, err := e.store.Load()
	if err != nil {
		return err
	}
	if !ok {
		return e.persistLocked()
	}
	if st.Version != diskVersion {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidState, st.Version)
	}
	e.rule = st.Rule
	if e.rule <= 0 {
		e.rule = 1
	}
	e.nextTask = st.NextTask
	if e.nextTask == 0 {
		e.nextTask = 1
	}
	e.nextJob = st.NextJob
	if e.nextJob == 0 {
		e.nextJob = 1
	}
	for _, dt := range st.Tasks {
		if dt == nil {
			continue
		}
		if _, exists := e.tasks[dt.ID]; exists {
			return fmt.Errorf("%w: duplicate task %d", ErrInvalidState, dt.ID)
		}
		if !e.tenantKnown(dt.Tenant) {
			return fmt.Errorf("%w: task %d has unknown tenant %q", ErrInvalidState, dt.ID, dt.Tenant)
		}
		if _, err := NormalizeDigest(string(dt.Digest)); err != nil {
			return fmt.Errorf("%w: task %d has bad digest", ErrInvalidState, dt.ID)
		}
		t := &task{
			id:        dt.ID,
			tenant:    dt.Tenant,
			digest:    dt.Digest,
			rule:      dt.Rule,
			jobID:     dt.JobID,
			state:     dt.State,
			attempts:  dt.Attempts,
			merged:    dt.Merged,
			requestID: dt.RequestID,
			reason:    dt.Reason,
			result:    dt.Result,
		}
		if t.result != nil {
			if err := t.result.Validate(); err != nil {
				return fmt.Errorf("%w: task %d: %v", ErrInvalidState, t.id, err)
			}
			if t.result.TaskID != t.id || t.result.Tenant != t.tenant || t.result.Digest != t.digest {
				return fmt.Errorf("%w: task %d result identity mismatch", ErrInvalidState, t.id)
			}
		}
		switch t.state {
		case StateQueued, StateScanning:
			t.state = StateFailed
			t.reason = "engine restarted before the scan committed"
			t.result = nil
		case StateReleasing:
			t.state = StateClean
			t.reason = "release interrupted by restart; file remains in quarantine"
			if t.result != nil {
				t.result.Released = false
				t.result.ReleasePath = ""
				t.result.ReleaseError = t.reason
			}
		case StateClean, StateInfected, StateFailed, StateCancelled, StateReleased:
			// valid persisted states
		default:
			return fmt.Errorf("%w: task %d has state %q", ErrInvalidState, t.id, t.state)
		}
		if t.state == StateReleased && (t.result == nil || !t.result.Released) {
			return fmt.Errorf("%w: task %d released without a released result", ErrInvalidState, t.id)
		}
		if t.state != StateReleased && t.result != nil && t.result.Released {
			t.state = StateReleased
		}
		if t.rule == 0 {
			t.rule = t.resultRule()
		}
		if t.id >= e.nextTask {
			e.nextTask = t.id + 1
		}
		if t.result != nil {
			key := jobKey(t.tenant, t.digest, t.result.RuleVersion)
			if _, exists := e.cache[key]; !exists {
				e.cache[key] = cachedOutcome{verdict: t.result.Verdict, reason: t.result.Reason}
			}
		}
		if t.requestID != "" {
			e.requests[requestKey(t.tenant, t.requestID)] = t.id
		}
		e.tasks[t.id] = t
	}
	for k, id := range st.Requests {
		if _, ok := e.tasks[id]; ok {
			e.requests[k] = id
		}
	}
	return e.persistLocked()
}

func (t *task) resultRule() RuleVersion {
	if t.result != nil {
		return t.result.RuleVersion
	}
	return 0
}

func (e *Engine) scanPath(d Digest) string {
	return e.store.BlobPath(d)
}

func requestKey(tenant Tenant, requestID string) string {
	return string(tenant) + "|" + requestID
}

// ErrRequestConflict reports a reused request ID carrying different content.
var ErrRequestConflict = errors.New("quarantine: request id reused with different content")

// ErrDigestMismatch reports content that does not match ExpectedDigest.
var ErrDigestMismatch = errors.New("quarantine: content does not match expected digest")

var _ = filepath.Separator // keep filepath available for platform-agnostic helpers
