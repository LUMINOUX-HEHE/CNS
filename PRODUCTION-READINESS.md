# Production Readiness — Trust Orchestrator

**Current tier: reference/demo — NOT production.** This file tracks the
gap between what ships today and what "production grade" requires. It is
the honest, executable companion to `docs/09-limitations.md`.

> Reaching production is a **multi-month program** (security audit, HSM
> integration, real multi-host deployment, DB migration, penetration
> testing, on-call/runbooks). This checklist is the plan, not a claim.

## Legend

- ✅ **done** — implemented and tested in this repo
- 🟡 **partial** — some of it exists; the gap is named
- ⬜ **todo** — not started; effort is a rough estimate

---

## 1. Scalability & correctness (code)

| # | Item | Status | Notes |
|---|---|---|---|
| S1 | CT log root is O(log n), not O(n) per STH | ✅ | `ctlog.go` incremental frontier; differential test `TestIncrementalRootMatchesReference` (sizes 1–1026) + `TestRootScalingIsLogarithmic` (100k leaves, ~500ns) |
| S2 | CT log persisted incrementally (survives restart without rebuild) | ✅ | `ctlog.json` snapshot (leaves+frontier) via `MerkleLog.Marshal/Unmarshal`; `Store.orgMerkle` is incremental (cached, O(log n) append) and `loadCTLog` catches up only new events. Tests: `TestMerkleLogMarshalRoundTrip`, `TestLoadCTLogCatchesUp`, `TestOrgMerkleIncrementalAndForkInvalidation` |
| S3 | Tenant storage: file-per-tenant → database with transactions | ⬜ (4–6 wk) | `store.go`: "file-per-tenant, no SQL. Linear scans" |
| S4 | Idempotency cache bounded (LRU), not unbounded map | ✅ | `lru.go` (container/list, concurrency-safe); `Store.idem` is `*LRU[string,idemEntry]`, true LRU eviction instead of whole-map clear |
| S5 | Webhook outbox: no torn writes (WAL/DB) | ✅ | `writeFileAtomic` fsyncs file+dir; drain no longer removes jobs before delivery (fixed silent drop of failed jobs); stable job IDs |
| S6 | Vault: DEK not co-located with payload | 🟡 | `vault.go:19` |

## 2. Security & secrets (the big one)

| # | Item | Status | Notes |
|---|---|---|---|
| K1 | Fail closed on weak/missing prod secrets | ✅ | `config.go` + `TO_PROFILE=prod`: bootstrap token, seal key, TLS, timeouts required; `TestLoadConfigProdFails` |
| K2 | HTTP server timeouts (slowloris) | ✅ | all four timeouts set from config with safe defaults |
| K3 | Secret storage in KMS/Vault/HSM, not env/file | ⬜ (3–5 wk) | `TO_SEAL_KEY_HEX` is the seam; back it with KMS |
| K4 | Hardware key custody (TPM/SGX) for root + council | ⬜ (6–10 wk) | `docs/09` D3 "semantic only" |
| K5 | Independent security audit / pen-test | ⬜ (4–8 wk, external) | mandatory before prod |
| K6 | Dependency & supply-chain policy | 🟡 | stdlib-only is a strength; add SBOM signing + provenance |
| K7 | Secrets never in logs/errors | 🟡 | audit needed across handlers |

## 3. Reliability & operations

| # | Item | Status | Notes |
|---|---|---|---|
| O1 | Real multi-host deployment proven | 🟡 | loopback mTLS real; cross-host not run (`docs/09` D1). `make fleet-smoke` + `deploy/*.service` |
| O2 | HA / leader failover automated | ⬜ (3–4 wk) | `cmd/gateway` leader-lock is manual failover |
| O3 | Backups: point-in-time + restore drill | 🟡 | backup/restore endpoints exist; no PITR |
| O4 | Observability: metrics/traces/alerting | 🟡 | `/v1/metrics` present; no Prometheus/OTel exporter, no SLOs |
| O5 | Runbooks + on-call + incident process | ⬜ (2 wk) | |
| O6 | Load/soak testing with capacity numbers | ⬜ (2–3 wk) | benchmark is in-process scenarios |
| O7 | Graceful shutdown / draining | ✅ | `cmd/gateway`: SIGINT/SIGTERM → `srv.Shutdown` drains in-flight requests up to the write timeout; outbox is durable so a hard stop loses nothing |

## 4. Statistics & detection quality

| # | Item | Status | Notes |
|---|---|---|---|
| D1 | Real p-value / calibrated detection stats | 🟡 | `CUSUM.PValue()` now returns the Wald boundary-crossing probability `exp(-2·delta·S/σ²)` (moves with S and the calibrated σ via `SetSigma`), replacing the hardcoded 0.01. Still needs calibration against real fleet data (D2/D3). Tests: `TestCUSUMPValueIsCalibrated`, `TestWatchdogScoreCarriesRealPValue` |
| D2 | Calibration against real wall-time fleet | 🟡 | in-process scenario clock (`docs/09` D6) |
| D3 | False-positive rate validated on production-like data | ⬜ | |

## 5. Compliance & transparency

| # | Item | Status | Notes |
|---|---|---|---|
| C1 | Transparency witnesses: real 2nd-party audit loop | 🟡 | log + proofs + gossip ship; independent poller is deployment (`docs/09` D15) |
| C2 | CRL: reason codes, delta CRLs, OCSP | 🟡 | `docs/09` D14 |
| C3 | Audit-log retention/immutability policy | ⬜ | |
| C4 | Regulatory mapping (if applicable) | ⬜ | |

---

## What this session changed (verified)

1. **S1 — CT log root is now O(log n).** `research/l0/ctlog.go` gained an
   incremental frontier; `Root()` folds it instead of rebuilding the tree.
   Proven byte-identical to the old implementation for every size 1–1026
   and shown ~30,000× faster at 100k leaves.
2. **K1/K2 — fail-closed production config.** `research/l0/config.go`
   adds `TO_PROFILE`, secret requirements, and HTTP timeouts, wired into
   `cmd/gateway`. `TO_PROFILE=prod` refuses to start with dev-grade
   settings. Dev behavior is unchanged (all existing tests still pass).

### Follow-up session (code track of the roadmap)

3. **S4 — bounded LRU idempotency cache.** `research/l0/lru.go` (stdlib
   `container/list`, concurrency-safe); `Store.idem` is now
   `*LRU[string,idemEntry]` — true LRU eviction replaces the whole-map
   clear at 4096 keys.
4. **S5 — durable webhook outbox.** `writeFileAtomic` fsyncs the file
   *and* its directory (no torn write, no lost job on power loss). Also
   fixed a real bug: `drainOutbox` removed due jobs before delivery, so
   a failed delivery was silently dropped and never retried. Jobs now
   carry a stable ID and stay queued until success or attempt exhaustion.
5. **S2 — persisted CT log frontier.** `MerkleLog.Marshal/Unmarshal`
   persist leaves+frontier to `tenants/<id>/ctlog.json`; `Store.orgMerkle`
   is incremental and cached (was an O(n) full rebuild on *every* CT
   request), and `loadCTLog` restores the snapshot and appends only new
   events. A recovery fork invalidates the cache.
6. **O7 — graceful shutdown.** `cmd/gateway` traps SIGINT/SIGTERM and
   drains via `srv.Shutdown` up to the write timeout.
7. **D1 — real p-values.** `CUSUM.PValue()` replaces the hardcoded 0.01
   with Wald's boundary-crossing probability `exp(-2·delta·S/σ²)`, a
   function of S and the calibrated σ (`Watchdog.SetSigma`). Calibration
   against real fleet data (D2/D3) is still open.

All of the above: `go build ./...`, `go vet ./...`, and `go test ./...`
(15 packages) pass.

## Recommended order from here

1. **K5 security audit** (external) — parallel with 2–3.
2. **K3 secrets → KMS** + **O1 real multi-host deploy** (prove it on 3 hosts).
3. **S3 database** (tenant storage; the remaining scale item).
4. **D1/D2 calibrated stats** against real fleet data (detection honesty).
5. **O2/O4/O5** (HA, observability, runbooks) before any customer traffic.

**Do not run this in front of untrusted traffic until K3–K5 and O1–O5 are done.**