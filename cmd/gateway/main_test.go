package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	to "trustorchestrator/research/l0"
)

// The dashboard embed and the API must both answer under the same handler.
func TestDashboardAndAPI(t *testing.T) {
	gw, token, err := to.NewGateway(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newHandler(gw))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Trust Orchestrator") {
		t.Fatalf("dashboard: %d, %d bytes", resp.StatusCode, len(body))
	}
	// Either the React SPA shell (div#root) or the legacy single-file
	// dashboard (id="token") is a valid UI at /.
	html := string(body)
	if !strings.Contains(html, "id=\"root\"") && !strings.Contains(html, "id=\"token\"") {
		t.Fatal("dashboard missing UI mount point")
	}

	// API still answers through the same mux
	req, _ := http.NewRequest("GET", srv.URL+"/v1/orgs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("api under dashboard mux: %d", resp.StatusCode)
	}
}
