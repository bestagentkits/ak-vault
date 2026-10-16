package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bestagentkits/ak-vault/go/akv1"
)

const (
	testIssuer   = "http://127.0.0.1:8788"
	testAudience = "http://127.0.0.1:8787"
	testEmail    = "device-owner@example.invalid"
)

// fakeWorker records revocation webhooks and checks their HMAC.
type fakeWorker struct {
	t      *testing.T
	secret string
	mu     sync.Mutex
	events []map[string]any
	status int
}

func (f *fakeWorker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	ts := r.Header.Get("AKV-Webhook-Timestamp")
	mac := hmac.New(sha256.New, []byte(f.secret))
	mac.Write([]byte(ts + "\n"))
	mac.Write(body)
	if base64.RawURLEncoding.EncodeToString(mac.Sum(nil)) != r.Header.Get("AKV-Webhook-Signature") {
		f.t.Errorf("webhook signature does not verify")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var ev map[string]any
	if err := json.Unmarshal(body, &ev); err != nil {
		f.t.Errorf("webhook body: %v", err)
	}
	f.mu.Lock()
	f.events = append(f.events, ev)
	status := f.status
	f.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
}

func newTestServer(t *testing.T) (*server, *httptest.Server, *fakeWorker) {
	t.Helper()
	worker := &fakeWorker{t: t}
	workerSrv := httptest.NewServer(worker)
	t.Cleanup(workerSrv.Close)
	cfg := config{issuer: testIssuer, audience: testAudience, webhookURL: workerSrv.URL, sharedDir: t.TempDir(),
		accessTTL: 15 * time.Minute, refreshTTL: time.Hour}
	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	worker.secret = srv.webhook.secret
	httpSrv := httptest.NewServer(srv.routes())
	t.Cleanup(httpSrv.Close)
	return srv, httpSrv, worker
}

func post(t *testing.T, url, bearer string, body any) (int, map[string]any) {
	t.Helper()
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func signIn(t *testing.T, base string) map[string]any {
	t.Helper()
	if code, _ := post(t, base+"/api/agentkit/auth/otp/start", "", map[string]string{"email": testEmail}); code != 200 {
		t.Fatalf("otp start: %d", code)
	}
	resp, err := http.Get(base + "/__e2e/otp?email=" + testEmail)
	if err != nil {
		t.Fatal(err)
	}
	var inbox map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&inbox)
	resp.Body.Close()
	code, login := post(t, base+"/api/agentkit/auth/otp/verify", "", map[string]string{"email": testEmail, "code": inbox["code"]})
	if code != 200 {
		t.Fatalf("otp verify: %d", code)
	}
	return login
}

type device struct {
	seed    []byte
	signPub string
}

func newDevice(t *testing.T) device {
	t.Helper()
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	pub, err := akv1.SignPublicKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	return device{seed: seed, signPub: akv1.B64Encode(pub)}
}

// tokenRequest builds the body the CLI's WebTokenSource posts.
func (d device) tokenRequest(t *testing.T, aud, sid string, ts int64) map[string]any {
	t.Helper()
	scope := []string{"vault:read", "vault:write"}
	sig, err := akv1.SignDetached(tokenRequestContext, map[string]any{"aud": aud, "scope": scope, "sid": sid, "sign_pub": d.signPub, "ts": ts}, d.seed)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"sign_pub": d.signPub, "scope": scope, "ts": ts, "sig": sig}
}

// verifyJWT checks an ES256 compact JWS against the issuer key and returns
// its header and claims.
func verifyJWT(t *testing.T, srv *server, token string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("token signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&srv.issuer.key.PublicKey, digest[:], r, s) {
		t.Fatal("token signature does not verify")
	}
	var header, claims map[string]any
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	c, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if json.Unmarshal(h, &header) != nil || json.Unmarshal(c, &claims) != nil {
		t.Fatal("token JSON")
	}
	return header, claims
}

func TestVaultTokenIsBoundToSessionAndDeviceKey(t *testing.T) {
	srv, base, _ := newTestServer(t)
	login := signIn(t, base.URL)
	if login["authMethod"] != "email_otp" || login["schemaVersion"] != float64(1) || login["refreshToken"] == "" || login["deviceId"] == "" {
		t.Fatalf("login response is not a complete renewable email session: %v", login)
	}
	dev := newDevice(t)
	sid := login["sessionId"].(string)
	code, resp := post(t, base.URL+tokenRoute, login["accessToken"].(string), dev.tokenRequest(t, testAudience, sid, time.Now().Unix()))
	if code != 200 {
		t.Fatalf("mint: %d %v", code, resp)
	}
	pub, _ := akv1.B64Decode(dev.signPub)
	if resp["did"] != akv1.Kid(pub) || resp["token_type"] != "Bearer" || resp["expires_in"] != float64(300) {
		t.Fatalf("token response: %v", resp)
	}
	header, claims := verifyJWT(t, srv, resp["access_token"].(string))
	if header["alg"] != "ES256" || header["typ"] != "at+jwt" || header["kid"] != srv.issuer.kid {
		t.Fatalf("header: %v", header)
	}
	if claims["iss"] != testIssuer || claims["aud"] != testAudience || claims["sid"] != sid || claims["did"] != resp["did"] ||
		claims["sub"] != login["user"].(map[string]any)["id"] || claims["scope"] != "vault:read vault:write" || claims["jti"] == "" {
		t.Fatalf("claims: %v", claims)
	}
	if claims["exp"].(float64)-claims["iat"].(float64) != 300 || claims["nbf"] != claims["iat"] {
		t.Fatalf("lifetime claims: %v", claims)
	}
}

func TestVaultTokenRefusals(t *testing.T) {
	_, base, _ := newTestServer(t)
	login := signIn(t, base.URL)
	access, sid := login["accessToken"].(string), login["sessionId"].(string)
	dev := newDevice(t)
	now := time.Now().Unix()

	cases := []struct {
		name   string
		bearer string
		body   map[string]any
		status int
		code   string
	}{
		{"no session", "", dev.tokenRequest(t, testAudience, sid, now), 401, "not_authenticated"},
		{"unknown session", "e2e-session-unknown", dev.tokenRequest(t, testAudience, sid, now), 401, "not_authenticated"},
		{"signed for another audience", access, dev.tokenRequest(t, "http://127.0.0.1:9999", sid, now), 401, "invalid_signature"},
		{"signed for another session", access, dev.tokenRequest(t, testAudience, "e2e-sid-other", now), 401, "invalid_signature"},
		{"stale request", access, dev.tokenRequest(t, testAudience, sid, now-120), 400, "stale_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, resp := post(t, base.URL+tokenRoute, tc.bearer, tc.body)
			if code != tc.status || resp["errorCode"] != tc.code {
				t.Fatalf("got %d %v, want %d %s", code, resp, tc.status, tc.code)
			}
		})
	}
	t.Run("signature from another device key", func(t *testing.T) {
		body := dev.tokenRequest(t, testAudience, sid, now)
		body["sign_pub"] = newDevice(t).signPub
		if code, resp := post(t, base.URL+tokenRoute, access, body); code != 401 || resp["errorCode"] != "invalid_signature" {
			t.Fatalf("got %d %v", code, resp)
		}
	})
	t.Run("unknown scope", func(t *testing.T) {
		body := dev.tokenRequest(t, testAudience, sid, now)
		body["scope"] = []string{"vault:admin"}
		if code, resp := post(t, base.URL+tokenRoute, access, body); code != 400 || resp["errorCode"] != "invalid_scope" {
			t.Fatalf("got %d %v", code, resp)
		}
	})
	t.Run("unknown field", func(t *testing.T) {
		body := dev.tokenRequest(t, testAudience, sid, now)
		body["extra"] = true
		if code, _ := post(t, base.URL+tokenRoute, access, body); code != 400 {
			t.Fatalf("got %d", code)
		}
	})
}

func TestSignInRefusesNonSyntheticAndReusedCodes(t *testing.T) {
	_, base, _ := newTestServer(t)
	if code, _ := post(t, base.URL+"/api/agentkit/auth/otp/start", "", map[string]string{"email": "someone@example.com"}); code != 400 {
		t.Fatalf("a non-synthetic address was accepted: %d", code)
	}
	login := signIn(t, base.URL)
	if login["accessToken"] == "" {
		t.Fatal("no access token")
	}
	// The code was consumed by the first verify.
	if code, _ := post(t, base.URL+"/api/agentkit/auth/otp/verify", "", map[string]string{"email": testEmail, "code": "000000"}); code != 401 {
		t.Fatalf("verify without a live challenge: %d", code)
	}
}

func TestRefreshRotatesAndLogoutRevokesAtTheWorker(t *testing.T) {
	_, base, worker := newTestServer(t)
	login := signIn(t, base.URL)
	oldRefresh := login["refreshToken"].(string)
	code, rotated := post(t, base.URL+"/api/agentkit/auth/refresh", "", map[string]string{"refreshToken": oldRefresh})
	if code != 200 || rotated["sessionId"] != login["sessionId"] || rotated["accessToken"] == login["accessToken"] {
		t.Fatalf("refresh: %d %v", code, rotated)
	}
	if code, _ := post(t, base.URL+"/api/agentkit/auth/refresh", "", map[string]string{"refreshToken": oldRefresh}); code != 401 {
		t.Fatalf("a used refresh token worked again: %d", code)
	}
	if code, _ := post(t, base.URL+tokenRoute, login["accessToken"].(string), map[string]any{}); code != 401 {
		t.Fatalf("the replaced access token still authenticates: %d", code)
	}

	access := rotated["accessToken"].(string)
	if code, _ := post(t, base.URL+"/api/agentkit/auth/sessions/current/revoke", access, map[string]any{}); code != 200 {
		t.Fatalf("revoke: %d", code)
	}
	worker.mu.Lock()
	events := worker.events
	worker.mu.Unlock()
	if len(events) != 1 {
		t.Fatalf("worker got %d webhook events, want 1", len(events))
	}
	sids, _ := events[0]["revoke_sids"].([]any)
	if events[0]["v"] != float64(1) || events[0]["event_id"] == "" || len(sids) != 1 || sids[0] != login["sessionId"] {
		t.Fatalf("webhook body: %v", events[0])
	}
	if code, _ := post(t, base.URL+"/api/agentkit/auth/refresh", "", map[string]string{"refreshToken": rotated["refreshToken"].(string)}); code != 401 {
		t.Fatalf("a revoked session renewed: %d", code)
	}
}

func TestRevokedDeviceGetsNoToken(t *testing.T) {
	_, base, worker := newTestServer(t)
	login := signIn(t, base.URL)
	dev := newDevice(t)
	pub, _ := akv1.B64Decode(dev.signPub)
	did := akv1.Kid(pub)
	if code, _ := post(t, base.URL+"/__e2e/revoke", "", map[string]any{"revoke_dids": []string{did}}); code != 200 {
		t.Fatalf("admin revoke: %d", code)
	}
	code, resp := post(t, base.URL+tokenRoute, login["accessToken"].(string), dev.tokenRequest(t, testAudience, login["sessionId"].(string), time.Now().Unix()))
	if code != 403 || resp["errorCode"] != "device_revoked" {
		t.Fatalf("got %d %v", code, resp)
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if len(worker.events) != 1 {
		t.Fatalf("worker got %d events", len(worker.events))
	}
}

func TestWebhookTreatsConflictAsDeliveredAndRetries5xx(t *testing.T) {
	srv, _, worker := newTestServer(t)
	worker.status = http.StatusConflict
	if err := srv.webhook.deliver(t.Context(), revocationBatch{RevokeSIDs: []string{"e2e-sid-x"}}); err != nil {
		t.Fatalf("409 must count as delivered: %v", err)
	}
	worker.mu.Lock()
	worker.status = http.StatusServiceUnavailable
	worker.events = nil
	worker.mu.Unlock()
	if err := srv.webhook.deliver(t.Context(), revocationBatch{RevokeSIDs: []string{"e2e-sid-y"}}); err == nil {
		t.Fatal("a persistent 503 was reported as delivered")
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if len(worker.events) != webhookAttempts {
		t.Fatalf("%d attempts, want %d", len(worker.events), webhookAttempts)
	}
	ids := map[any]bool{}
	for _, ev := range worker.events {
		ids[ev["event_id"]] = true
	}
	if len(ids) != 1 {
		t.Fatal("retries must reuse the event ID")
	}
}

// webhook_only feeds the Worker but leaves the session valid at fake-akweb,
// so the e2e can show the Worker itself refuses a revoked session.
func TestWebhookOnlyRevokeKeepsTheSessionAtFakeAkweb(t *testing.T) {
	_, base, worker := newTestServer(t)
	login := signIn(t, base.URL)
	sid := login["sessionId"].(string)
	if code, _ := post(t, base.URL+"/__e2e/revoke", "", map[string]any{"revoke_sids": []string{sid}, "webhook_only": true}); code != 200 {
		t.Fatalf("admin revoke: %d", code)
	}
	dev := newDevice(t)
	code, resp := post(t, base.URL+tokenRoute, login["accessToken"].(string), dev.tokenRequest(t, testAudience, sid, time.Now().Unix()))
	if code != 200 {
		t.Fatalf("webhook_only revoked the session at fake-akweb: %d %v", code, resp)
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if len(worker.events) != 1 {
		t.Fatalf("worker got %d events", len(worker.events))
	}
	sids, _ := worker.events[0]["revoke_sids"].([]any)
	if len(sids) != 1 || sids[0] != sid {
		t.Fatalf("worker event revoke_sids = %v", worker.events[0]["revoke_sids"])
	}
}
