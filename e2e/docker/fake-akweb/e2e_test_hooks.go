package main

// Test hooks under /__e2e/. They stand in for what a person does outside
// the CLI: reading the OTP email, or revoking a session or device on the
// ak-web account page. The stack's network is internal, so only the
// containers of this stack can reach them. They never return tokens.

import (
	"net/http"
	"strings"
)

const maxHookEntries = 16

func (s *server) registerTestHooks(mux *http.ServeMux) {
	mux.HandleFunc("GET /__e2e/otp", s.handleReadInbox)
	mux.HandleFunc("POST /__e2e/revoke", s.handleAdminRevoke)
	mux.HandleFunc("GET /__e2e/stats", s.handleStats)
}

// handleReadInbox returns the last OTP sent to a synthetic address.
func (s *server) handleReadInbox(w http.ResponseWriter, r *http.Request) {
	email := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
	if !validEmail(email) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	code, ok := s.accounts.readInbox(email)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": code})
}

// handleAdminRevoke revokes sessions and vault devices, as the ak-web
// account page does, and feeds the Worker's revocation registry. With
// webhook_only it only sends the webhook and keeps fake-akweb's own sessions
// and devices valid, so a refusal the device then sees can only come from the
// Worker honouring the webhook.
func (s *server) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RevokeSIDs  []string `json:"revoke_sids"`
		RevokeDIDs  []string `json:"revoke_dids"`
		WebhookOnly bool     `json:"webhook_only"`
	}
	if err := decodeStrict(r, &body); err != nil ||
		len(body.RevokeSIDs)+len(body.RevokeDIDs) == 0 ||
		len(body.RevokeSIDs) > maxHookEntries || len(body.RevokeDIDs) > maxHookEntries {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	for _, v := range append(append([]string{}, body.RevokeSIDs...), body.RevokeDIDs...) {
		if v == "" || len(v) > 256 {
			writeError(w, http.StatusBadRequest, "invalid_request")
			return
		}
	}
	if !body.WebhookOnly {
		for _, sid := range body.RevokeSIDs {
			s.accounts.revoke(sid)
		}
		for _, did := range body.RevokeDIDs {
			s.accounts.revokeDevice(did)
		}
	}
	if err := s.webhook.deliver(r.Context(), revocationBatch{RevokeSIDs: body.RevokeSIDs, RevokeDIDs: body.RevokeDIDs}); err != nil {
		writeError(w, http.StatusBadGateway, "vault_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *server) handleStats(w http.ResponseWriter, _ *http.Request) {
	delivered, failed := s.webhook.stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"registry":           s.accounts.snapshotStats(),
		"webhooks_delivered": delivered,
		"webhooks_failed":    failed,
	})
}
