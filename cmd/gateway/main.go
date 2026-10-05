// to-gateway: the management plane — REST API, RBAC, multi-tenancy, webhooks,
// backup/restore over the trust engine, plus the web dashboard at /.
// State lives under -data.
//
//	to-gateway -addr :8080 -data ./data
//	to-gateway -addr :8443 -tls-cert cert.pem -tls-key key.pem   # TLS
//	to-gateway -council-pub <hex>                                # recovery anchor
//
// First boot prints the admin token (or -token/TO_ADMIN_TOKEN seeds it).
package main

import (
	"context"
	"crypto/ed25519"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	to "trustorchestrator/research/l0"
)

//go:embed all:dist
var distFS embed.FS

//go:embed dashboard.html
var dashboardFS embed.FS

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	data := flag.String("data", "./data", "state directory")
	token := flag.String("token", os.Getenv("TO_ADMIN_TOKEN"), "admin bootstrap token (first boot only)")
	tlsCert := flag.String("tls-cert", "", "server certificate (enables TLS; needs tls-key)")
	tlsKey := flag.String("tls-key", "", "server private key")
	council := flag.String("council-pub", os.Getenv("TO_COUNCIL_PUB"), "hex council FROST group key — recovery trust anchor")
	lock := flag.String("leader-lock", "", "peer file: HA single-writer lease (second gateway exits)")
	kekShares := flag.String("kek-shares", "", "council KEK share files, comma-separated — 3-of-5 threshold unwrap for gateway.keys (envelope encryption, vault.go)")
	flag.Parse()

	// Production config: TO_PROFILE=prod fails closed on weak/missing
	// secrets (bootstrap token, seal key, TLS). dev (default) is unchanged.
	cfg, err := to.LoadConfig()
	if err != nil {
		log.Fatalf("gateway: %v", err)
	}
	// Flags win over env; env fills what the flag left empty.
	if *data == "./data" && cfg.DataDir != "" && cfg.DataDir != "." {
		*data = cfg.DataDir
	}
	if *token == "" {
		*token = cfg.BootstrapToken
	}
	if *tlsCert == "" && cfg.TLSCert != "" {
		*tlsCert, *tlsKey = cfg.TLSCert, cfg.TLSKey
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("gateway: tls-cert and tls-key must be set together")
	}
	if cfg.Profile == to.ProfileProd && *tlsCert == "" {
		log.Fatal("gateway: TO_PROFILE=prod requires in-process TLS (tls-cert/tls-key)")
	}
	if *lock != "" {
		acquireLeaderLock(*lock)
		defer os.Remove(*lock)
	}

	gw, raw, err := to.NewGateway(*data, *token)
	if err != nil {
		log.Fatalf("gateway: %v", err)
	}
	if *kekShares != "" {
		shares, err := loadShares(*kekShares)
		if err != nil {
			log.Fatalf("gateway: kek-shares: %v", err)
		}
		if err := gw.UnlockVault(shares); err != nil {
			log.Fatalf("gateway: vault unwrap: %v", err)
		}
		log.Printf("vault: envelope encryption active (council KEK, unwrapped by %d share files)", len(shares))
	}
	if *council != "" {
		pub, err := hex2key(*council)
		if err != nil {
			log.Fatalf("gateway: council-pub: %v", err)
		}
		if err := gw.SetCouncilPub(pub); err != nil {
			log.Fatalf("gateway: set council anchor: %v", err)
		}
	}
	gw.StartWebhookOutbox() // durable delivery on top of the gateway store
	if raw != "" {
		fmt.Printf("admin token (shown once): %s\n", raw)
	}

	readHeader, read, write, idle := cfg.ServerTimeouts()
	srv := &http.Server{
		Addr:              *addr,
		Handler:           newHandler(gw),
		ReadHeaderTimeout: readHeader,
		ReadTimeout:       read,
		WriteTimeout:      write,
		IdleTimeout:       idle,
	}
	// Graceful shutdown (O7): on SIGINT/SIGTERM stop accepting connections,
	// drain in-flight requests for up to the write timeout, then exit. The
	// webhook outbox is already durable, so a hard stop loses nothing.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	if *tlsCert != "" {
		log.Printf("trust orchestrator gateway on https://%s (data: %s, council: %t)", *addr, *data, *council != "")
		go func() { serveErr <- srv.ListenAndServeTLS(*tlsCert, *tlsKey) }()
	} else {
		log.Printf("trust orchestrator gateway on http://%s (data: %s, council: %t)", *addr, *data, *council != "")
		go func() { serveErr <- srv.ListenAndServe() }()
	}

	select {
	case err := <-serveErr:
		// A real listen/serve failure (e.g. bind) is fatal. Graceful
		// shutdown never reaches this case: ctx.Done() wins and drains.
		if err != nil {
			log.Fatal(err)
		}
	case <-ctx.Done():
		log.Printf("gateway: shutdown signal — draining (up to %s)", write)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), write)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("gateway: drain incomplete: %v", err)
			srv.Close()
		}
		log.Printf("gateway: stopped")
	}
}

// hex2key decodes a hex-encoded council FROST group key (32-byte Ed25519).
func hex2key(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("want %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// loadShares reads the council KEK share files (Shard JSON, one per member).
func loadShares(list string) ([]*to.Shard, error) {
	var shares []*to.Shard
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var sh to.Shard
		if err := json.Unmarshal(b, &sh); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		shares = append(shares, &sh)
	}
	if len(shares) == 0 {
		return nil, fmt.Errorf("no share files given")
	}
	return shares, nil
}

// newHandler mounts the React SPA at / and the REST API at /v1/*. If the
// SPA was not built (no cmd/gateway/dist/index.html), it falls back to the
// legacy single-file dashboard so the gateway always has a UI.
func newHandler(gw *to.Store) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/v1/", gw.Handler())
	if _, err := distFS.ReadFile("dist/index.html"); err != nil {
		dash, _ := dashboardFS.ReadFile("dashboard.html")
		mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(dash)
		})
		return mux
	}
	mux.HandleFunc("/", spaHandler)
	return mux
}

// spaHandler serves the built React app: real asset files by path, and
// index.html for every other path so client-side routing (deep links like
// /transparency) resolves without a server round-trip 404.
func spaHandler(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "" {
		p = "index.html"
	}
	if b, err := distFS.ReadFile("dist/" + p); err == nil {
		w.Header().Set("Content-Type", contentType(p))
		w.Write(b)
		return
	}
	idx, _ := distFS.ReadFile("dist/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(idx)
}

func contentType(p string) string {
	switch {
	case strings.HasSuffix(p, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(p, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(p, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(p, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(p, ".json"):
		return "application/json"
	default:
		return "application/octet-stream"
	}
}

// acquireLeaderLock makes one gateway the single writer over a data dir:
// the lock file is created exclusively; a second process exits. HA = one
// active replica + the outbox survives restarts (ponytail: manual failover
// — the new replica takes over when the file is removed).
func acquireLeaderLock(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatalf("gateway: leader lock %s held by another instance (HA single-writer)", path)
	}
	fmt.Fprintf(f, "%d\n", os.Getpid())
	f.Close()
}
