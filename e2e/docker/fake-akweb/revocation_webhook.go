package main

// The revocation feed to the Worker (spec §9.3): POST the batch with
// AKV-Webhook-Timestamp and AKV-Webhook-Signature = b64url(HMAC-SHA256(
// secret, ts "\n" body)). A 409 means the event was already applied and
// counts as delivered; network errors and 5xx are retried.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/bestagentkits/ak-vault/go/akv1"
)

const (
	webhookAttempts = 5
	webhookBackoff  = 500 * time.Millisecond
)

// revocationBatch is the body the Worker accepts.
type revocationBatch struct {
	RevokeSIDs []string       `json:"revoke_sids"`
	RevokeDIDs []string       `json:"revoke_dids"`
	MinIat     []minIatRecord `json:"min_iat"`
}

type minIatRecord struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
}

type webhookSender struct {
	url    string
	secret string
	client *http.Client
	now    func() time.Time

	mu        sync.Mutex
	delivered int
	failed    int
}

func newWebhookSender(url, secret string) *webhookSender {
	return &webhookSender{url: url, secret: secret, client: &http.Client{Timeout: 5 * time.Second}, now: time.Now}
}

// body renders the wire body for one event.
func (w *webhookSender) body(eventID string, b revocationBatch) ([]byte, error) {
	nonNil := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	minIat := b.MinIat
	if minIat == nil {
		minIat = []minIatRecord{}
	}
	return json.Marshal(map[string]any{
		"v": 1, "event_id": eventID, "revoke_sids": nonNil(b.RevokeSIDs), "revoke_dids": nonNil(b.RevokeDIDs), "min_iat": minIat,
	})
}

// sign returns the timestamp and signature headers for body.
func (w *webhookSender) sign(ts int64, body []byte) (string, string) {
	tsText := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(w.secret))
	mac.Write([]byte(tsText + "\n"))
	mac.Write(body)
	return tsText, base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// deliver sends one revocation event, retrying transient failures.
func (w *webhookSender) deliver(ctx context.Context, b revocationBatch) error {
	body, err := w.body(akv1.RandomID(), b)
	if err != nil {
		return err
	}
	var last error
	for attempt := 0; attempt < webhookAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(webhookBackoff * time.Duration(attempt)):
			}
		}
		status, err := w.post(ctx, body)
		switch {
		case err != nil:
			last = err
		case status == http.StatusOK || status == http.StatusConflict:
			w.count(true)
			return nil
		case status >= 500:
			last = fmt.Errorf("webhook: HTTP %d", status)
		default:
			w.count(false)
			return fmt.Errorf("webhook refused: HTTP %d", status)
		}
	}
	w.count(false)
	return last
}

func (w *webhookSender) post(ctx context.Context, body []byte) (int, error) {
	// A fresh timestamp per attempt keeps a retry inside the ±300 s window.
	ts, sig := w.sign(w.now().Unix(), body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("AKV-Webhook-Timestamp", ts)
	req.Header.Set("AKV-Webhook-Signature", sig)
	resp, err := w.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("webhook: %w", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func (w *webhookSender) count(ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ok {
		w.delivered++
	} else {
		w.failed++
	}
}

func (w *webhookSender) stats() (delivered, failed int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.delivered, w.failed
}
