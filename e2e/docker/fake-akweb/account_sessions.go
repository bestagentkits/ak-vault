package main

// Synthetic accounts and CLI sessions: the email OTP sign-in, renewal and
// revocation contract of the CLI's auth client
// (apps/cli/internal/runtime/auth/client.go in agentkit). One email is one
// account, so two devices signed in with the same address are two devices
// of one account, as with the real ak-web.

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/bestagentkits/ak-vault/go/akv1"
)

// Prefixes of the synthetic credentials this service issues. The disclosure
// scan searches the Worker's state and logs for them.
const (
	accessTokenPrefix  = "e2e-session-"
	refreshTokenPrefix = "e2e-refresh-"
	sessionIDPrefix    = "e2e-sid-"
	accountPrefix      = "e2e-account-"
	authDevicePrefix   = "e2e-authdev-"
)

// syntheticEmailDomain is the only domain that can sign in; it is reserved
// (RFC 6761), so no real person's address can be used here.
const syntheticEmailDomain = "@example.invalid"

const (
	otpLifetime    = 10 * time.Minute
	otpMaxAttempts = 5
)

var (
	errNotAuthenticated = errors.New("not_authenticated")
	errInvalidRequest   = errors.New("invalid_request")
)

type otpChallenge struct {
	code     string
	expires  time.Time
	attempts int
}

// session is one CLI email sign-in.
type session struct {
	sid          string
	account      string
	email        string
	authDeviceID string
	accessToken  string
	accessExp    time.Time
	refreshToken string
	refreshExp   time.Time
	revoked      bool
}

// loginResponse mirrors auth.LoginResponse for an email sign-in.
type loginResponse struct {
	SchemaVersion         int       `json:"schemaVersion"`
	Token                 string    `json:"token"`
	AccessToken           string    `json:"accessToken"`
	RefreshToken          string    `json:"refreshToken"`
	AccessTokenExpiresAt  string    `json:"accessTokenExpiresAt"`
	RefreshTokenExpiresAt string    `json:"refreshTokenExpiresAt"`
	SessionID             string    `json:"sessionId"`
	User                  loginUser `json:"user"`
	AuthMethod            string    `json:"authMethod"`
	DeviceID              string    `json:"deviceId"`
}

type loginUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type accountRegistry struct {
	accessTTL, refreshTTL time.Duration

	mu        sync.Mutex
	accounts  map[string]string // email -> account ID
	otps      map[string]*otpChallenge
	mailbox   map[string]string   // email -> last OTP issued (the e2e "inbox")
	sessions  map[string]*session // sid -> session
	byAccess  map[string]string   // access token -> sid
	byRefresh map[string]string   // refresh token -> sid
	// revokedDIDs are vault device keys ak-web no longer mints tokens for.
	revokedDIDs map[string]bool
	stats       registryStats
}

type registryStats struct {
	SignIns   int `json:"sign_ins"`
	Refreshes int `json:"refreshes"`
	Revokes   int `json:"revokes"`
	Minted    int `json:"minted"`
}

func newAccountRegistry(accessTTL, refreshTTL time.Duration) *accountRegistry {
	return &accountRegistry{
		accessTTL: accessTTL, refreshTTL: refreshTTL,
		accounts: map[string]string{}, otps: map[string]*otpChallenge{}, mailbox: map[string]string{},
		sessions: map[string]*session{}, byAccess: map[string]string{}, byRefresh: map[string]string{},
		revokedDIDs: map[string]bool{},
	}
}

// validEmail accepts only a lower-case synthetic address.
func validEmail(email string) bool {
	local, ok := strings.CutSuffix(email, syntheticEmailDomain)
	if !ok || local == "" || len(email) > 254 {
		return false
	}
	for _, c := range local {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '+') {
			return false
		}
	}
	return true
}

// startOTP issues a fresh 6-digit code to the synthetic inbox.
func (a *accountRegistry) startOTP(email string, now time.Time) error {
	if !validEmail(email) {
		return errInvalidRequest
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return fmt.Errorf("otp: %w", err)
	}
	code := fmt.Sprintf("%06d", n.Int64())
	a.mu.Lock()
	defer a.mu.Unlock()
	a.otps[email] = &otpChallenge{code: code, expires: now.Add(otpLifetime)}
	a.mailbox[email] = code
	return nil
}

// readInbox returns the last code sent to email (the e2e mailbox hook).
func (a *accountRegistry) readInbox(email string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	code, ok := a.mailbox[email]
	return code, ok
}

// verifyOTP checks a code once and opens a session.
func (a *accountRegistry) verifyOTP(email, code string, now time.Time) (loginResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ch, ok := a.otps[email]
	if !ok || now.After(ch.expires) {
		delete(a.otps, email)
		return loginResponse{}, errNotAuthenticated
	}
	ch.attempts++
	if subtle.ConstantTimeCompare([]byte(ch.code), []byte(code)) != 1 {
		if ch.attempts >= otpMaxAttempts {
			delete(a.otps, email)
		}
		return loginResponse{}, errNotAuthenticated
	}
	delete(a.otps, email)
	delete(a.mailbox, email)
	account, ok := a.accounts[email]
	if !ok {
		account = accountPrefix + akv1.RandomID()
		a.accounts[email] = account
	}
	s := &session{sid: sessionIDPrefix + akv1.RandomID(), account: account, email: email, authDeviceID: authDevicePrefix + akv1.RandomID()}
	a.issueTokensLocked(s, now)
	a.sessions[s.sid] = s
	a.stats.SignIns++
	return a.responseLocked(s), nil
}

// refresh rotates a session's token pair; a refresh token works once.
func (a *accountRegistry) refresh(refreshToken string, now time.Time) (loginResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sid, ok := a.byRefresh[refreshToken]
	if !ok {
		return loginResponse{}, errNotAuthenticated
	}
	s := a.sessions[sid]
	if s == nil || s.revoked || now.After(s.refreshExp) {
		return loginResponse{}, errNotAuthenticated
	}
	a.issueTokensLocked(s, now)
	a.stats.Refreshes++
	return a.responseLocked(s), nil
}

// issueTokensLocked replaces s's token pair. The caller holds a.mu.
func (a *accountRegistry) issueTokensLocked(s *session, now time.Time) {
	delete(a.byAccess, s.accessToken)
	delete(a.byRefresh, s.refreshToken)
	s.accessToken = accessTokenPrefix + akv1.RandomID()
	s.refreshToken = refreshTokenPrefix + akv1.RandomID()
	s.accessExp = now.Add(a.accessTTL)
	s.refreshExp = now.Add(a.refreshTTL)
	a.byAccess[s.accessToken] = s.sid
	a.byRefresh[s.refreshToken] = s.sid
}

func (a *accountRegistry) responseLocked(s *session) loginResponse {
	return loginResponse{
		SchemaVersion: 1, Token: s.accessToken, AccessToken: s.accessToken, RefreshToken: s.refreshToken,
		AccessTokenExpiresAt:  s.accessExp.UTC().Format(time.RFC3339Nano),
		RefreshTokenExpiresAt: s.refreshExp.UTC().Format(time.RFC3339Nano),
		SessionID:             s.sid, User: loginUser{ID: s.account, Email: s.email},
		AuthMethod: "email_otp", DeviceID: s.authDeviceID,
	}
}

// authenticate returns the live session an access token belongs to.
func (a *accountRegistry) authenticate(accessToken string, now time.Time) (session, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	sid, ok := a.byAccess[accessToken]
	if !ok {
		return session{}, errNotAuthenticated
	}
	s := a.sessions[sid]
	if s == nil || s.revoked || now.After(s.accessExp) {
		return session{}, errNotAuthenticated
	}
	return *s, nil
}

// revoke ends the session named by sid and drops its tokens. It reports
// whether a live session was revoked.
func (a *accountRegistry) revoke(sid string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.sessions[sid]
	if s == nil || s.revoked {
		return false
	}
	s.revoked = true
	delete(a.byAccess, s.accessToken)
	delete(a.byRefresh, s.refreshToken)
	a.stats.Revokes++
	return true
}

// revokeDevice refuses future vault tokens for a vault device key, as
// ak-web does once a user revokes a device on the web.
func (a *accountRegistry) revokeDevice(did string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revokedDIDs[did] = true
}

func (a *accountRegistry) deviceRevoked(did string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.revokedDIDs[did]
}

func (a *accountRegistry) countMint() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stats.Minted++
}

func (a *accountRegistry) snapshotStats() registryStats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stats
}
