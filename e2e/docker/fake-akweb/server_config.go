package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// config is the service configuration, read from the environment.
type config struct {
	listenAddr string
	// issuer is the ak-web origin the CLI talks to (AGENTKIT_REGISTRY_URL
	// on the devices), every token's iss, and the Worker's VAULT_ISSUER.
	issuer string
	// audience is the vault origin tokens are minted for: the Worker's
	// VAULT_AUDIENCE and the CLI's --vault-origin.
	audience string
	// webhookURL is where revocations are delivered (the Worker's
	// /internal/v1/revocations, reached over the compose network).
	webhookURL string
	// sharedDir receives jwks.json and webhook-secret for the vault service.
	sharedDir string
	// accessTTL bounds a CLI access token; the CLI renews it on
	// not_authenticated with its refresh token.
	accessTTL  time.Duration
	refreshTTL time.Duration
}

func configFromEnv() (config, error) {
	cfg := config{
		listenAddr: envOr("FAKE_AKWEB_LISTEN", ":8788"),
		issuer:     envOr("FAKE_AKWEB_ISSUER", "http://127.0.0.1:8788"),
		audience:   envOr("FAKE_AKWEB_AUDIENCE", "http://127.0.0.1:8787"),
		webhookURL: envOr("FAKE_AKWEB_WEBHOOK_URL", "http://vault:8787/internal/v1/revocations"),
		sharedDir:  envOr("FAKE_AKWEB_SHARED_DIR", "/shared"),
		refreshTTL: 30 * 24 * time.Hour,
	}
	ttl, err := time.ParseDuration(envOr("FAKE_AKWEB_ACCESS_TTL", "15m"))
	if err != nil || ttl < time.Minute || ttl > 24*time.Hour {
		return config{}, errors.New("FAKE_AKWEB_ACCESS_TTL must be a duration between 1m and 24h")
	}
	cfg.accessTTL = ttl
	for name, origin := range map[string]string{"FAKE_AKWEB_ISSUER": cfg.issuer, "FAKE_AKWEB_AUDIENCE": cfg.audience} {
		if !isOrigin(origin) {
			return config{}, fmt.Errorf("%s must be a bare http(s) origin", name)
		}
	}
	if u, err := url.Parse(cfg.webhookURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return config{}, errors.New("FAKE_AKWEB_WEBHOOK_URL must be an http(s) URL")
	}
	return cfg, nil
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

// isOrigin reports whether raw is scheme://host[:port] with nothing else.
func isOrigin(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" &&
		u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.User == nil
}

// server holds the issuer key, the account and session registry, and the
// webhook sender.
type server struct {
	cfg      config
	issuer   *issuer
	accounts *accountRegistry
	webhook  *webhookSender
	now      func() time.Time
}

func newServer(cfg config) (*server, error) {
	iss, err := newIssuer(cfg.issuer, cfg.audience)
	if err != nil {
		return nil, err
	}
	secret, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	return &server{
		cfg:      cfg,
		issuer:   iss,
		accounts: newAccountRegistry(cfg.accessTTL, cfg.refreshTTL),
		webhook:  newWebhookSender(cfg.webhookURL, secret),
		now:      time.Now,
	}, nil
}

// writeSharedFiles publishes the public JWKS and the webhook HMAC secret
// for the vault service, which reads them at startup. The directory is a
// volume shared only with the vault service.
func (s *server) writeSharedFiles() error {
	if err := os.MkdirAll(s.cfg.sharedDir, 0o700); err != nil {
		return fmt.Errorf("shared dir: %w", err)
	}
	jwks, err := json.Marshal(s.issuer.jwks())
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(s.cfg.sharedDir, "jwks.json"), jwks); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(s.cfg.sharedDir, "webhook-secret"), []byte(s.webhook.secret))
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("publish %s: %w", filepath.Base(path), err)
	}
	return nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// routes is the ak-web surface plus the e2e test hooks.
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.issuer.jwks())
	})
	mux.HandleFunc("POST /api/agentkit/auth/otp/start", s.handleOTPStart)
	mux.HandleFunc("POST /api/agentkit/auth/otp/verify", s.handleOTPVerify)
	mux.HandleFunc("POST /api/agentkit/auth/refresh", s.handleRefresh)
	mux.HandleFunc("POST /api/agentkit/auth/sessions/current/revoke", s.handleRevokeCurrent)
	mux.HandleFunc("POST "+tokenRoute, s.handleVaultToken)
	s.registerTestHooks(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not_found")
	})
	return logRequests(mux)
}
