package l0

// config.go — production configuration. The historical binary read no
// environment at all (all defaults hardcoded). This layer makes the
// deployment knobs explicit and *fail closed*: a production profile
// refuses to start with development-grade settings rather than silently
// running insecure. Development defaults are unchanged, so every existing
// test and the demo keep working without setting anything.

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Profile selects how strictly the gateway validates its own config.
type Profile string

const (
	// ProfileDev keeps the historical permissive behavior (default).
	ProfileDev Profile = "dev"
	// ProfileProd enables fail-closed validation: weak keys, missing
	// secrets and unset limits are startup errors, not warnings.
	ProfileProd Profile = "prod"
)

// Config is the resolved runtime configuration.
type Config struct {
	Profile Profile

	// DataDir is where gateway.json, gateway.key and tenants/ live.
	DataDir string

	// BootstrapToken seeds the first admin. In prod it MUST come from the
	// environment and MUST be high-entropy; the dev default is generated.
	BootstrapToken string

	// SealKeyHex, when set, pins the 32-byte at-rest encryption key
	// (AES-GCM). In prod this comes from a secret store / KMS, not the
	// on-disk gateway.key, so a stolen data dir is not a stolen key.
	SealKeyHex string

	// ReadHeaderTimeout / ReadTimeout / WriteTimeout / IdleTimeout are the
	// HTTP server timeouts. Zero means "use the safe production default"
	// (never the Go zero = no timeout, which is a slowloris vector).
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration

	// TLSCert/TLSKey, when both set, terminate TLS in-process.
	TLSCert string
	TLSKey  string
}

// ErrInsecureConfig is returned when a production profile finds a
// development-grade setting. Callers must treat it as fatal.
var ErrInsecureConfig = errors.New("l0: refusing to start with insecure production config")

// LoadConfig reads configuration from the environment. Unset variables
// fall back to safe defaults; in ProfileProd the validators then reject
// anything unsafe. It never reads secrets from files implicitly — the
// caller decides where the seal key comes from.
func LoadConfig() (*Config, error) {
	c := &Config{
		Profile:           Profile(strings.ToLower(envOr("TO_PROFILE", string(ProfileDev)))),
		DataDir:           envOr("TO_DATA_DIR", "."),
		BootstrapToken:    os.Getenv("TO_BOOTSTRAP_TOKEN"),
		SealKeyHex:        os.Getenv("TO_SEAL_KEY_HEX"),
		ReadHeaderTimeout: durationOr("TO_READ_HEADER_TIMEOUT", 10*time.Second),
		ReadTimeout:       durationOr("TO_READ_TIMEOUT", 30*time.Second),
		WriteTimeout:      durationOr("TO_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:       durationOr("TO_IDLE_TIMEOUT", 120*time.Second),
		TLSCert:           os.Getenv("TO_TLS_CERT"),
		TLSKey:            os.Getenv("TO_TLS_KEY"),
	}
	if c.Profile != ProfileDev && c.Profile != ProfileProd {
		return nil, fmt.Errorf("l0: unknown TO_PROFILE %q (want dev|prod)", c.Profile)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate enforces the profile's rules. Dev accepts everything; prod
// fails closed on the documented blockers (D10 dev bootstrap key, D3
// no secret manager, plus missing TLS and absent timeouts).
func (c *Config) Validate() error {
	if c.DataDir == "" {
		return fmt.Errorf("%w: TO_DATA_DIR is empty", ErrInsecureConfig)
	}
	if c.Profile != ProfileProd {
		return nil
	}
	var problems []string
	if len(c.BootstrapToken) < 32 {
		problems = append(problems, "TO_BOOTSTRAP_TOKEN must be set and >= 32 chars in prod (no dev default)")
	}
	if len(c.SealKeyHex) != 64 {
		problems = append(problems, "TO_SEAL_KEY_HEX must be a 32-byte hex key from a secret store (64 hex chars)")
	}
	if c.TLSCert == "" || c.TLSKey == "" {
		problems = append(problems, "TO_TLS_CERT and TO_TLS_KEY must both be set (terminate TLS in-process or front it with a proxy and set TO_TLS_TERMINATED=1)")
	}
	if c.ReadHeaderTimeout <= 0 || c.ReadTimeout <= 0 || c.WriteTimeout <= 0 {
		problems = append(problems, "HTTP timeouts must be > 0")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w:\n  - %s", ErrInsecureConfig, strings.Join(problems, "\n  - "))
	}
	return nil
}

// ServerTimeouts returns HTTP server timeouts with safe production
// defaults applied when unset (Go's zero value means "no timeout").
func (c *Config) ServerTimeouts() (readHeader, read, write, idle time.Duration) {
	readHeader, read, write, idle = c.ReadHeaderTimeout, c.ReadTimeout, c.WriteTimeout, c.IdleTimeout
	if readHeader <= 0 {
		readHeader = 10 * time.Second
	}
	if read <= 0 {
		read = 30 * time.Second
	}
	if write <= 0 {
		write = 30 * time.Second
	}
	if idle <= 0 {
		idle = 120 * time.Second
	}
	return
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func durationOr(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

// intOr is used by callers that add numeric limits.
func intOr(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}