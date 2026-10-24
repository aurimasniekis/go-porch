// Package metrics defines Porch's Prometheus metrics. Every method is safe on a nil *Metrics (metrics disabled).
// Label values are bounded enums or route patterns; tenant names, user IDs and emails are never used as labels.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// TxResult classifies a write transaction outcome.
type TxResult string

// Transaction results.
const (
	TxOK         TxResult = "ok"
	TxCanceled   TxResult = "canceled"
	TxBusy       TxResult = "busy"
	TxFull       TxResult = "full"
	TxIO         TxResult = "io"
	TxCorrupt    TxResult = "corrupt"
	TxConstraint TxResult = "constraint"
	TxConflict   TxResult = "conflict"
	TxNotFound   TxResult = "not_found"
	TxError      TxResult = "error"
)

// Metrics holds every Porch collector in its own registry.
type Metrics struct {
	reg *prometheus.Registry

	storeTx       *prometheus.HistogramVec
	storeBusy     prometheus.Counter
	storeWait     prometheus.Histogram
	storeQueue    prometheus.Gauge
	storeDBBytes  prometheus.Gauge
	storeWALBytes prometheus.Gauge

	httpReqs *prometheus.CounterVec
	httpDur  *prometheus.HistogramVec

	logins       *prometheus.CounterVec
	lockouts     prometheus.Counter
	auditEvents  *prometheus.CounterVec
	authz        *prometheus.CounterVec
	tokensIssued *prometheus.CounterVec
	outboxQueue  *prometheus.GaugeVec
	outboxPub    *prometheus.CounterVec
	jobRuns      *prometheus.CounterVec
	backupLast   *prometheus.GaugeVec
	backupRuns   *prometheus.CounterVec
	ready        prometheus.Gauge
	buildInfo    *prometheus.GaugeVec
}

const ns = "porch"

// New registers every collector in a fresh registry (plus Go runtime and process collectors).
func New() *Metrics {
	m := &Metrics{reg: prometheus.NewRegistry()}
	m.storeTx = prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Subsystem: "store", Name: "tx_duration_seconds",
		Help: "Write transaction duration by name and result.", Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5}},
		[]string{"tx", "result"})
	m.storeBusy = prometheus.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "store", Name: "tx_busy_retries_total",
		Help: "Write transaction attempts retried after SQLITE_BUSY."})
	m.storeWait = prometheus.NewHistogram(prometheus.HistogramOpts{Namespace: ns, Subsystem: "store", Name: "writer_wait_seconds",
		Help: "Time waiting for the single writer connection and its write lock.", Buckets: prometheus.DefBuckets})
	m.storeQueue = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "store", Name: "writer_queue",
		Help: "Write transactions waiting for the writer."})
	m.storeDBBytes = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "store", Name: "db_bytes", Help: "Database file size."})
	m.storeWALBytes = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Subsystem: "store", Name: "wal_bytes", Help: "WAL file size."})
	m.httpReqs = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "http", Name: "requests_total",
		Help: "HTTP requests by surface, method and status class."}, []string{"surface", "method", "code"})
	m.httpDur = prometheus.NewHistogramVec(prometheus.HistogramOpts{Namespace: ns, Subsystem: "http", Name: "request_duration_seconds",
		Help: "HTTP request duration by surface.", Buckets: prometheus.DefBuckets}, []string{"surface"})
	m.logins = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "auth", Name: "logins_total",
		Help: "Login attempts by method and outcome."}, []string{"method", "outcome"})
	m.lockouts = prometheus.NewCounter(prometheus.CounterOpts{Namespace: ns, Subsystem: "auth", Name: "backup_lockouts_total",
		Help: "Backup-login lockouts applied."})
	m.auditEvents = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "audit", Name: "events_total",
		Help: "Audit events appended by outcome."}, []string{"outcome"})
	m.authz = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "authz", Name: "decisions_total",
		Help: "Authorization decisions by result and reason."}, []string{"result", "reason"})
	m.tokensIssued = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "oidc", Name: "tokens_issued_total",
		Help: "Tokens issued by kind."}, []string{"kind"})
	m.outboxQueue = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Subsystem: "outbox", Name: "events",
		Help: "Outbox events by state (pending, dead)."}, []string{"state"})
	m.outboxPub = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "outbox", Name: "publish_total",
		Help: "Outbox publish attempts by result."}, []string{"result"})
	m.jobRuns = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "jobs", Name: "runs_total",
		Help: "Background job runs by kind and result."}, []string{"kind", "result"})
	m.backupLast = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Subsystem: "backup", Name: "last_timestamp_seconds",
		Help: "Unix time of the last backup run by result."}, []string{"result"})
	m.backupRuns = prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: ns, Subsystem: "backup", Name: "runs_total",
		Help: "Backup runs by result."}, []string{"result"})
	m.ready = prometheus.NewGauge(prometheus.GaugeOpts{Namespace: ns, Name: "ready", Help: "1 when the instance reports ready."})
	m.buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: ns, Name: "build_info", Help: "Build information."},
		[]string{"version", "go_version"})
	m.reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.storeTx, m.storeBusy, m.storeWait, m.storeQueue, m.storeDBBytes, m.storeWALBytes, m.httpReqs, m.httpDur,
		m.logins, m.lockouts, m.auditEvents, m.authz, m.tokensIssued, m.outboxQueue, m.outboxPub, m.jobRuns,
		m.backupLast, m.backupRuns, m.ready, m.buildInfo)
	return m
}

// Registry returns the underlying registry.
func (m *Metrics) Registry() *prometheus.Registry {
	if m == nil {
		return nil
	}
	return m.reg
}

// Handler serves the registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}

// StoreTx records a finished write transaction.
func (m *Metrics) StoreTx(name string, d time.Duration, r TxResult) {
	if m == nil {
		return
	}
	if name == "" {
		name = "unnamed"
	}
	m.storeTx.WithLabelValues(name, string(r)).Observe(d.Seconds())
}

// StoreTxBusyRetry counts a busy retry.
func (m *Metrics) StoreTxBusyRetry() {
	if m != nil {
		m.storeBusy.Inc()
	}
}

// StoreWriterWait records writer wait time.
func (m *Metrics) StoreWriterWait(d time.Duration) {
	if m != nil {
		m.storeWait.Observe(d.Seconds())
	}
}

// StoreWriterQueue adjusts the writer queue gauge.
func (m *Metrics) StoreWriterQueue(delta int) {
	if m != nil {
		m.storeQueue.Add(float64(delta))
	}
}

// SetStoreSizes exports database and WAL sizes.
func (m *Metrics) SetStoreSizes(dbBytes, walBytes int64) {
	if m != nil {
		m.storeDBBytes.Set(float64(dbBytes))
		m.storeWALBytes.Set(float64(walBytes))
	}
}

// HTTPRequest records one HTTP request on a surface (portal, api, oidc, outpost, mgmt).
func (m *Metrics) HTTPRequest(surface, method string, status int, d time.Duration) {
	if m == nil {
		return
	}
	m.httpReqs.WithLabelValues(surface, methodLabel(method), strconv.Itoa(status/100)+"xx").Inc()
	m.httpDur.WithLabelValues(surface).Observe(d.Seconds())
}

func methodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return method
	}
	return "other"
}

// Login counts a login attempt (method: google, backup, recovery_link, setup; outcome: success, failure, locked, denied).
func (m *Metrics) Login(method, outcome string) {
	if m != nil {
		m.logins.WithLabelValues(method, outcome).Inc()
	}
}

// BackupLockout counts an applied lockout.
func (m *Metrics) BackupLockout() {
	if m != nil {
		m.lockouts.Inc()
	}
}

// AuditEvent counts an appended audit event.
func (m *Metrics) AuditEvent(outcome string) {
	if m != nil {
		m.auditEvents.WithLabelValues(outcome).Inc()
	}
}

// AuthzDecision counts an authorization decision.
func (m *Metrics) AuthzDecision(allowed bool, reason string) {
	if m == nil {
		return
	}
	r := "deny"
	if allowed {
		r = "allow"
	}
	m.authz.WithLabelValues(r, reason).Inc()
}

// TokenIssued counts an issued token (id_token, access_token, refresh_token, code).
func (m *Metrics) TokenIssued(kind string) {
	if m != nil {
		m.tokensIssued.WithLabelValues(kind).Inc()
	}
}

// SetOutbox exports outbox backlog.
func (m *Metrics) SetOutbox(pending, dead int) {
	if m != nil {
		m.outboxQueue.WithLabelValues("pending").Set(float64(pending))
		m.outboxQueue.WithLabelValues("dead").Set(float64(dead))
	}
}

// OutboxPublish counts a publish attempt (ok, error, auth_error, dead).
func (m *Metrics) OutboxPublish(result string) {
	if m != nil {
		m.outboxPub.WithLabelValues(result).Inc()
	}
}

// JobRun counts a job execution.
func (m *Metrics) JobRun(kind string, err error) {
	if m == nil {
		return
	}
	r := "ok"
	if err != nil {
		r = "error"
	}
	m.jobRuns.WithLabelValues(kind, r).Inc()
}

// BackupRun records a backup run.
func (m *Metrics) BackupRun(ok bool, at time.Time) {
	if m == nil {
		return
	}
	r := "failure"
	if ok {
		r = "success"
	}
	m.backupRuns.WithLabelValues(r).Inc()
	m.backupLast.WithLabelValues(r).Set(float64(at.Unix()))
}

// SetReady exports readiness.
func (m *Metrics) SetReady(ready bool) {
	if m == nil {
		return
	}
	v := 0.0
	if ready {
		v = 1
	}
	m.ready.Set(v)
}

// SetBuildInfo exports version labels.
func (m *Metrics) SetBuildInfo(version, goVersion string) {
	if m != nil {
		m.buildInfo.WithLabelValues(version, goVersion).Set(1)
	}
}
