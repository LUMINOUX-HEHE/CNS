# Trust Orchestrator — React control panel

A full-fledged React + TypeScript SPA that drives the gateway REST API
end to end: orgs, issue/revoke, watchdog detection, recovery, audit,
users, webhooks, metrics, backup/restore, and the RFC 9162 transparency
log. Built with Vite and served by the same Go binary that runs the API.

## Run against the live gateway

The built app is embedded into `cmd/gateway` (`go:embed all:dist`) and
served at `/`, so the normal way to use it is simply:

make build              # builds the gateway (uses the committed dist/)
go run ./cmd/gateway -addr :8080 -data ./data
# first boot prints: admin token (shown once): <TOKEN>
# open http://localhost:8080/ and paste the token
## Develop with hot reload

# terminal 1 — the API
go run ./cmd/gateway -addr :8080 -data ./data

# terminal 2 — Vite dev server on :5173, proxying /v1 -> :8080
make ui-dev             # or: cd frontend && npm install && npm run dev
# open http://localhost:5173/
The dev server proxies `/v1` to `localhost:8080` (see `vite.config.ts`),
so there is no CORS friction in development.

## Rebuild the embedded bundle

After changing anything under `frontend/src`, rebuild the bundle that
the Go binary embeds:

make ui-build           # cd frontend && npm install && npm run build
# writes to cmd/gateway/dist/ (embedded by go:embed all:dist)
## Pages

| Page | What it does |
|---|---|
| Overview | create/list orgs, health badges, event counts |
| Org | issue/revoke certs, post watchdog scores, council recovery, timeline, trust state |
| Transparency | signed tree head + inclusion/consistency proofs (RFC 9162) |
| Audit | search timeline events by org/type/identity/cert |
| Users | create users, roles, org scoping, token counts |
| Webhooks | register/delete webhook endpoints |
| Metrics | per-org cards + raw Prometheus text |
| Backup | create snapshot, download, restore from file |

## Stack

- React 18 + React Router 6
- TypeScript
- Vite 5 (build + dev server with API proxy)
- No UI framework — hand-rolled CSS matching the gateway's ops console
  look, so the whole app is one dependency tree and no design system.

## Layout

frontend/
  index.html
  vite.config.ts        build -> ../cmd/gateway/dist, dev proxy /v1
  package.json
  src/
    main.tsx            app entry (BrowserRouter + AuthProvider)
    App.tsx             shell: sidebar nav + routes
    auth.tsx            token context (localStorage)
    api.ts              typed fetch client (Bearer auth, errors)
    lib.tsx             useAsync hook, Flash, PageHead, formatters
    types.ts            API response types
    pages/              one file per page
    styles.css