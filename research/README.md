# TrustFabric — research program

The TrustFabric research program. Each layer is its **own project
folder** containing its Go package and a `doc/` folder with that layer's
normative specification. `doc/` at the top holds the program-level
documents.

research/
|-- README.md                    this file
|-- doc/                         program-level documents
|   |-- 00-executive-summary.md
|   |-- 01-system-architecture.md
|   `-- 08-research-roadmap.md
|-- l0/                          L0 trust engine + seam contract
|   |-- seam.go
|   `-- doc/02-L0-trust-engine.md
|-- l1/                          cross-org consensus (WQBFT)
|   |-- wqbft.go  recovery.go  sim.go  wqbft_test.go
|   `-- doc/03-L1-cross-org-consensus.md
|-- l2/                          private transparency
|   |-- private.go  private_test.go
|   `-- doc/04-L2-private-transparency.md
|-- l3/                          threat intelligence
|   |-- intel.go  intel_test.go
|   `-- doc/05-L3-threat-intelligence.md
|-- l4/                          trust economics
|   |-- economics.go  economics_test.go
|   `-- doc/06-L4-trust-economics.md
|-- l5/                          formal verification
|   |-- verify.go  verify_test.go
|   `-- doc/07-L5-formal-verification.md
`-- integration/                 end-to-end loop test
    `-- integration_test.go
## Projects

| Project | Layer | Code | Doc |
|---|---|---|---|
| `l0/` | L0 seam contract | signed observations, fingerprint registry, trust-edge graph, envelope | `l0/doc/02` |
| `l1/` | L1 | WQBFT weighted-quorum consensus, commit certs, federated recovery (cross-org FROST), simulator | `l1/doc/03` |
| `l2/` | L2 | INCLUDE / EXTENDS / NONE_OF / COUNT_OF claims, conditional disclosure | `l2/doc/04` |
| `l3/` | L3 | pairwise-mask secure aggregation, Laplace DP + budget ledger, noise-aware CUSUM, correlation, signed RISK_FEED + L0 gate | `l3/doc/05` |
| `l4/` | L4 | update rule U, signed score ledger, proper scoring, recovery commitments, sybil analysis, agent sim | `l4/doc/06` |
| `l5/` | L5 | property ledger + adversarial seam harness | `l5/doc/07` |
| `integration/` | all | L0 -> L2 -> L3 -> L4 -> L1 -> recovery loop | `doc/08` §8 |

## Run

go test ./research/...
## Honest status vs. the specs

Each layer's spec describes a *research* end state (zk-SNARKs, F* proof
terms, full MPC, production BFT). The implementation carries the same
interfaces and properties so the research target can be swapped in
without changing callers:

- **L2** is sound and hiding, but **not zero-knowledge** (proof structure
  leaks) — the boundary in `l2/doc/04` §5. The SNARK backend replaces
  `Prove*`/`Verify*` bodies.
- **L5** marks a property `PROVEN` only when the adversarial harness
  finds no violating input *and* the Go suite passes; else `STATED` /
  `FAILED`, per `l5/doc/07` §6. F*/Coq proof terms are the remaining half.
- **L3** uses a two-aggregator honest-majority model (`l3/doc/05` §4.1),
  not full MPC; upgrade path is the L1 cluster.
- **L1** is synchronous-delivery; asynchrony (DAG-Rider) is `l1/doc/03` §10.