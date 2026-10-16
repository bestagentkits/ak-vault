// Command fake-akweb stands in for ak-web in the Docker two-device e2e
// stack. It implements only the ak-web contract the AgentKit CLI and the
// ak-vault Worker use:
//
//   - email OTP sign-in, session refresh and session revoke (the CLI's
//     `ak login --email`, its automatic renewal, and `ak logout`);
//   - the vault token route of spec §9 (ES256 at+jwt bound to the session
//     ID and to the device key that signed the request);
//   - the public JWKS of its ephemeral issuer key;
//   - the HMAC-signed revocation webhook to the Worker (spec §9.3).
//
// Every key and secret is generated at startup and lives only in memory and
// in the stack's shared volume. Accounts are synthetic: only addresses under
// example.invalid can sign in. The token route logic is ported from
// agentkit's in-process e2e fake registry
// (apps/cli/internal/runtime/secretsync/e2e/fake_registry_test.go).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// The image has no shell or curl, so the compose healthcheck runs the
	// binary itself.
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	if err := run(); err != nil {
		log.Printf("fake-akweb: %v", err)
		os.Exit(1)
	}
}

// healthcheck probes the local /healthz and returns the process exit code.
func healthcheck() int {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1" + envOr("FAKE_AKWEB_LISTEN", ":8788") + "/healthz")
	if err != nil {
		return 1
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}

func run() error {
	cfg, err := configFromEnv()
	if err != nil {
		return err
	}
	srv, err := newServer(cfg)
	if err != nil {
		return err
	}
	if err := srv.writeSharedFiles(); err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errs := make(chan error, 1)
	go func() { errs <- httpServer.ListenAndServe() }()
	log.Printf("fake-akweb: listening on %s, issuer %s, audience %s", cfg.listenAddr, cfg.issuer, cfg.audience)
	select {
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", err)
		}
		return nil
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}
