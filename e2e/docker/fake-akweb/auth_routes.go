package main

// HTTP handlers for the CLI's sign-in, renewal and logout calls.

import (
	"errors"
	"net/http"
	"strings"
)

func (s *server) handleOTPStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := decodeStrict(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := s.accounts.startOTP(strings.ToLower(strings.TrimSpace(body.Email)), s.now()); err != nil {
		if errors.Is(err, errInvalidRequest) {
			writeError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *server) handleOTPVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := decodeStrict(r, &body); err != nil || body.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	resp, err := s.accounts.verifyOTP(strings.ToLower(strings.TrimSpace(body.Email)), body.Code, s.now())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := decodeStrict(r, &body); err != nil || body.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	resp, err := s.accounts.refresh(body.RefreshToken, s.now())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleRevokeCurrent is `ak logout`: it ends the session and tells the
// Worker, so a vault token minted for it is refused before it expires.
func (s *server) handleRevokeCurrent(w http.ResponseWriter, r *http.Request) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	sess, err := s.accounts.authenticate(bearer, s.now())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "not_authenticated")
		return
	}
	s.accounts.revoke(sess.sid)
	if err := s.webhook.deliver(r.Context(), revocationBatch{RevokeSIDs: []string{sess.sid}}); err != nil {
		// The session is revoked here either way; the Worker refusal is what
		// failed, and the caller sees that as a server error to retry.
		writeError(w, http.StatusBadGateway, "vault_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
