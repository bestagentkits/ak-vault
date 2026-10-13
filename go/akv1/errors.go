package akv1

import (
	"errors"
	"fmt"
)

// Stable error codes (spec §10) plus the client-side code CodeDecryptFailed
// (spec §11). They are identical to the TypeScript reference implementation.
const (
	CodeUnauthorized        = "unauthorized"
	CodeForbidden           = "forbidden"
	CodeNotFound            = "not_found"
	CodeConflict            = "conflict"
	CodeTombstoned          = "tombstoned"
	CodeRekeyRequired       = "rekey_required"
	CodeUnsupportedVersion  = "unsupported_version"
	CodeInvalidSignature    = "invalid_signature"
	CodeRollback            = "rollback"
	CodeRateLimited         = "rate_limited"
	CodeQuotaExceeded       = "quota_exceeded"
	CodeIdempotencyMismatch = "idempotency_mismatch"
	CodeSyncDisabled        = "sync_disabled"
	CodeBadRequest          = "bad_request"
	CodeDecryptFailed       = "decrypt_failed"
)

// ErrorCodes lists every stable code in the same order as the TypeScript
// `AKV_ERROR_CODES` constant.
var ErrorCodes = []string{
	CodeUnauthorized, CodeForbidden, CodeNotFound, CodeConflict, CodeTombstoned,
	CodeRekeyRequired, CodeUnsupportedVersion, CodeInvalidSignature, CodeRollback,
	CodeRateLimited, CodeQuotaExceeded, CodeIdempotencyMismatch, CodeSyncDisabled,
	CodeBadRequest, CodeDecryptFailed,
}

// Error is the only error type returned by this package. Code is one of the
// Code* constants; Message is diagnostic text that never contains secret
// values, names, tokens or request bodies.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("akv1 %s: %s", e.Code, e.Message)
}

// CodeOf returns the protocol code of err, or "" when err is nil or not an *Error.
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func newErr(code, format string, args ...any) *Error {
	if len(args) == 0 {
		return &Error{Code: code, Message: format}
	}
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

func badRequest(format string, args ...any) *Error {
	return newErr(CodeBadRequest, format, args...)
}
