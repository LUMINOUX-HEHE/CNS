package l0

import (
	"errors"
	"testing"
)

// TestLoadConfigDevPermissive: the default profile must not require any
// environment, so existing deployments and tests are unaffected.
func TestLoadConfigDevPermissive(t *testing.T) {
	t.Setenv("TO_PROFILE", "dev")
	c, err := LoadConfig()
	if err != nil {
		t.Fatalf("dev config must load with no env: %v", err)
	}
	if c.Profile != ProfileDev {
		t.Fatalf("profile = %q", c.Profile)
	}
	rh, r, w, i := c.ServerTimeouts()
	if rh <= 0 || r <= 0 || w <= 0 || i <= 0 {
		t.Fatal("dev timeouts must still be safe defaults")
	}
}

// TestLoadConfigProdFails: a prod profile with no secrets must be a
// startup error, never a silent insecure boot.
func TestLoadConfigProdFails(t *testing.T) {
	t.Setenv("TO_PROFILE", "prod")
	t.Setenv("TO_BOOTSTRAP_TOKEN", "")
	t.Setenv("TO_SEAL_KEY_HEX", "")
	t.Setenv("TO_TLS_CERT", "")
	t.Setenv("TO_TLS_KEY", "")
	_, err := LoadConfig()
	if err == nil {
		t.Fatal("prod with no secrets must fail closed")
	}
	if !errors.Is(err, ErrInsecureConfig) {
		t.Fatalf("want ErrInsecureConfig, got %v", err)
	}
}

// TestLoadConfigProdAcceptsStrongConfig: a fully configured prod profile
// must load.
func TestLoadConfigProdAcceptsStrongConfig(t *testing.T) {
	t.Setenv("TO_PROFILE", "prod")
	t.Setenv("TO_DATA_DIR", t.TempDir())
	t.Setenv("TO_BOOTSTRAP_TOKEN", "0123456789abcdef0123456789abcdef")
	t.Setenv("TO_SEAL_KEY_HEX", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	t.Setenv("TO_TLS_CERT", "/etc/to/tls.crt")
	t.Setenv("TO_TLS_KEY", "/etc/to/tls.key")
	if _, err := LoadConfig(); err != nil {
		t.Fatalf("strong prod config rejected: %v", err)
	}
}

// TestUnknownProfileRejected: a typo in TO_PROFILE must not silently
// downgrade to dev.
func TestUnknownProfileRejected(t *testing.T) {
	t.Setenv("TO_PROFILE", "production")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("unknown profile must be rejected")
	}
}