package akv1

// Relay frames (spec §9.7): the WebSocket protocol through which the Worker
// hands a remote MCP tool call to one of the account's online devices. Each
// frame is one canonical cjson text frame with exactly the keys of its type.

// Signing contexts of relay frames.
const (
	ContextRelay       = "akv1/relay"
	ContextRelayResult = "akv1/relay-result"
)

// Relay frame types (closed set).
const (
	RelayHello  = "hello"
	RelayReady  = "ready"
	RelayReauth = "reauth"
	RelayCall   = "call"
	RelayResult = "result"
)

// Relay tools (closed set) and the MCP scopes that cover them.
const (
	ToolSearch   = "search"
	ToolList     = "list"
	ToolDescribe = "describe"
	ToolSet      = "set"
	ToolDelete   = "delete"
	ToolRequest  = "request"
	ToolRun      = "run"

	ScopeMCPRead  = "vault-mcp:read"
	ScopeMCPWrite = "vault-mcp:write"
	ScopeMCPUse   = "vault-mcp:use"
)

// Relay result error codes (closed set).
const (
	RelayErrDenied          = "denied"
	RelayErrPendingApproval = "pending_approval"
	RelayErrNotFound        = "not_found"
	RelayErrInvalidArgs     = "invalid_args"
	RelayErrConflict        = "conflict"
	RelayErrUnsupported     = "unsupported"
	RelayErrInternal        = "internal"
)

// Session kinds of a sync token's session_kind claim (spec §9 item 1).
const (
	SessionKindEmailOTP     = "email_otp"
	SessionKindAPIKeyDevice = "api_key_device"
	SessionKindMachine      = "machine"
	SessionKindBrowser      = "browser"
)

// RelayFrameMaxBytes is the initial relay_frame_max_bytes (spec §10); the
// deployment publishes the value in force in GET /v1/meta.
const RelayFrameMaxBytes = 131072

var (
	relayFrameTypes = []string{RelayHello, RelayReady, RelayReauth, RelayCall, RelayResult}
	RelayTools      = []string{ToolSearch, ToolList, ToolDescribe, ToolSet, ToolDelete, ToolRequest, ToolRun}
	mcpScopes       = []string{ScopeMCPRead, ScopeMCPWrite, ScopeMCPUse}
	relayErrorCodes = []string{RelayErrDenied, RelayErrPendingApproval, RelayErrNotFound, RelayErrInvalidArgs, RelayErrConflict, RelayErrUnsupported, RelayErrInternal}
	relayToolScopes = map[string]string{ToolSearch: ScopeMCPRead, ToolList: ScopeMCPRead, ToolDescribe: ScopeMCPRead, ToolSet: ScopeMCPWrite, ToolDelete: ScopeMCPWrite, ToolRequest: ScopeMCPUse, ToolRun: ScopeMCPUse}
	maxRelayVaults  = 16
)

// ToolScope returns the MCP scope a relay tool needs ("" for an unknown tool).
func ToolScope(tool string) string { return relayToolScopes[tool] }

// RelayCaller identifies the MCP client behind a call.
type RelayCaller struct {
	ClientID string
	GrantID  string
	Scopes   []string
}

// JSONValue returns the wire object.
func (c RelayCaller) JSONValue() any {
	return map[string]any{"client_id": c.ClientID, "grant_id": c.GrantID, "scopes": stringsToAny(c.Scopes)}
}

// Covers reports whether the caller's scopes cover tool.
func (c RelayCaller) Covers(tool string) bool {
	need := ToolScope(tool)
	return need != "" && contains(c.Scopes, need)
}

// RelayFrame is one parsed frame; Type selects the meaningful fields.
type RelayFrame struct {
	Type string

	// hello
	DeviceID string
	Vaults   []string
	Tools    []string
	TS       int64

	// ready
	Exp int64

	// reauth
	Token string
	Proof string

	// call (CallID is shared with result)
	CallID     string
	VaultID    string
	Tool       string
	Args       map[string]any
	Caller     RelayCaller
	DeadlineMs int64

	// result
	OK        bool
	Result    map[string]any
	ErrorCode string

	// hello and result
	Sig string
}

// JSONValue returns the wire object ("sig" omitted when empty).
func (f RelayFrame) JSONValue() any {
	m := map[string]any{"v": int64(1), "type": f.Type}
	switch f.Type {
	case RelayHello:
		m["device_id"], m["vaults"], m["tools"], m["ts"] = f.DeviceID, stringsToAny(f.Vaults), stringsToAny(f.Tools), f.TS
	case RelayReady:
		m["exp"] = f.Exp
	case RelayReauth:
		m["token"], m["proof"] = f.Token, f.Proof
	case RelayCall:
		args := f.Args
		if args == nil {
			args = map[string]any{}
		}
		m["call_id"], m["vault_id"], m["tool"], m["args"], m["caller"], m["deadline_ms"] = f.CallID, f.VaultID, f.Tool, args, f.Caller.JSONValue(), f.DeadlineMs
	case RelayResult:
		m["call_id"], m["ok"] = f.CallID, f.OK
		if f.OK {
			res := f.Result
			if res == nil {
				res = map[string]any{}
			}
			m["result"] = res
		} else {
			m["error"] = map[string]any{"code": f.ErrorCode}
		}
	}
	if f.Sig != "" && (f.Type == RelayHello || f.Type == RelayResult) {
		m["sig"] = f.Sig
	}
	return m
}

// RelayFrameOptions configures ParseRelayFrame.
type RelayFrameOptions struct {
	Binary   bool // the WebSocket frame was binary (always refused)
	MaxBytes int  // relay_frame_max_bytes in force; 0 means RelayFrameMaxBytes
}

// ParseRelayFrame validates one received WebSocket frame: a text frame of at
// most MaxBytes holding a canonical cjson object with exactly the keys of its
// type. v other than 1 is unsupported_version; anything else wrong is
// bad_request (close 4400). Signatures are checked by VerifyHello and
// VerifyResult.
func ParseRelayFrame(data []byte, opts RelayFrameOptions) (RelayFrame, error) {
	max := opts.MaxBytes
	if max <= 0 {
		max = RelayFrameMaxBytes
	}
	if opts.Binary {
		return RelayFrame{}, badRequest("relay frames must be text frames")
	}
	if len(data) > max {
		return RelayFrame{}, badRequest("relay frame exceeds %d bytes", max)
	}
	v, err := CJSONParse(data)
	if err != nil {
		return RelayFrame{}, err
	}
	return parseRelayFrameValue(v)
}

func parseRelayFrameValue(v any) (RelayFrame, error) {
	const what = "relay frame"
	obj, err := asObject(v, what)
	if err != nil {
		return RelayFrame{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return RelayFrame{}, err
	}
	typ, err := asEnum(obj["type"], relayFrameTypes, what+".type")
	if err != nil {
		return RelayFrame{}, err
	}
	f := RelayFrame{Type: typ}
	switch typ {
	case RelayHello:
		err = parseHello(obj, &f)
	case RelayReady:
		if err = exactKeys(obj, []string{"v", "type", "exp"}, what); err == nil {
			f.Exp, err = asUint(obj["exp"], what+".exp")
		}
	case RelayReauth:
		err = parseReauth(obj, &f)
	case RelayCall:
		err = parseCall(obj, &f)
	case RelayResult:
		err = parseResult(obj, &f)
	}
	if err != nil {
		return RelayFrame{}, err
	}
	return f, nil
}

func parseHello(obj map[string]any, f *RelayFrame) error {
	const what = "hello"
	if err := exactKeys(obj, []string{"v", "type", "device_id", "vaults", "tools", "ts", "sig"}, what); err != nil {
		return err
	}
	var err error
	if f.DeviceID, err = asID(obj["device_id"], what+".device_id"); err != nil {
		return err
	}
	if f.Vaults, err = asIDList(obj["vaults"], what+".vaults", maxRelayVaults); err != nil {
		return err
	}
	if len(f.Vaults) == 0 {
		return badRequest("%s.vaults must list 1..%d vaults", what, maxRelayVaults)
	}
	if f.Tools, err = asEnumSet(obj["tools"], RelayTools, what+".tools"); err != nil {
		return err
	}
	if len(f.Tools) == 0 {
		return badRequest("%s.tools must list at least one tool", what)
	}
	if f.TS, err = asUint(obj["ts"], what+".ts"); err != nil {
		return err
	}
	f.Sig, err = asB64(obj["sig"], what+".sig", 64)
	return err
}

func parseReauth(obj map[string]any, f *RelayFrame) error {
	const what = "reauth"
	if err := exactKeys(obj, []string{"v", "type", "token", "proof"}, what); err != nil {
		return err
	}
	var err error
	if f.Token, err = asString(obj["token"], what+".token", MaxSafeInteger, 1); err != nil {
		return err
	}
	f.Proof, err = asString(obj["proof"], what+".proof", MaxSafeInteger, 1)
	return err
}

func parseCall(obj map[string]any, f *RelayFrame) error {
	const what = "call"
	if err := exactKeys(obj, []string{"v", "type", "call_id", "vault_id", "tool", "args", "caller", "deadline_ms"}, what); err != nil {
		return err
	}
	var err error
	if f.CallID, err = asID(obj["call_id"], what+".call_id"); err != nil {
		return err
	}
	if f.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return err
	}
	if f.Tool, err = asEnum(obj["tool"], RelayTools, what+".tool"); err != nil {
		return err
	}
	if f.Args, err = asObject(obj["args"], what+".args"); err != nil {
		return err
	}
	caller, err := asObject(obj["caller"], what+".caller")
	if err != nil {
		return err
	}
	if err := exactKeys(caller, []string{"client_id", "grant_id", "scopes"}, what+".caller"); err != nil {
		return err
	}
	if f.Caller.ClientID, err = asPrintableASCII(caller["client_id"], what+".caller.client_id", 1, maxClientIDBytes); err != nil {
		return err
	}
	if f.Caller.GrantID, err = asPrintableASCII(caller["grant_id"], what+".caller.grant_id", 1, maxGrantIDBytes); err != nil {
		return err
	}
	if f.Caller.Scopes, err = asEnumSet(caller["scopes"], mcpScopes, what+".caller.scopes"); err != nil {
		return err
	}
	f.DeadlineMs, err = asInt(obj["deadline_ms"], what+".deadline_ms", 1, MaxSafeInteger)
	return err
}

func parseResult(obj map[string]any, f *RelayFrame) error {
	const what = "result"
	ok, isBool := obj["ok"].(bool)
	if !isBool {
		return badRequest("%s.ok must be a boolean", what)
	}
	f.OK = ok
	var err error
	if ok {
		err = exactKeys(obj, []string{"v", "type", "call_id", "ok", "result", "sig"}, what)
	} else {
		err = exactKeys(obj, []string{"v", "type", "call_id", "ok", "error", "sig"}, what)
	}
	if err != nil {
		return err
	}
	if f.CallID, err = asID(obj["call_id"], what+".call_id"); err != nil {
		return err
	}
	if ok {
		if f.Result, err = asObject(obj["result"], what+".result"); err != nil {
			return err
		}
	} else {
		e, err := asObject(obj["error"], what+".error")
		if err != nil {
			return err
		}
		if err := exactKeys(e, []string{"code"}, what+".error"); err != nil {
			return err
		}
		if f.ErrorCode, err = asEnum(e["code"], relayErrorCodes, what+".error.code"); err != nil {
			return err
		}
	}
	f.Sig, err = asB64(obj["sig"], what+".sig", 64)
	return err
}

// asEnumSet validates an array of unique values drawn from allowed.
func asEnumSet(v any, allowed []string, what string) ([]string, error) {
	arr, err := asArray(v, what, len(allowed))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s, err := asEnum(item, allowed, what+"[]")
		if err != nil {
			return nil, err
		}
		if contains(out, s) {
			return nil, badRequest("%s contains duplicates", what)
		}
		out = append(out, s)
	}
	return out, nil
}

// signRelayFrame signs f under context after validating its shape.
func signRelayFrame(f RelayFrame, typ, context string, seed []byte) (RelayFrame, error) {
	if f.Type != typ {
		return RelayFrame{}, badRequest("frame is not a %s frame", typ)
	}
	f.Sig = ""
	sig, err := SignDetached(context, f, seed)
	if err != nil {
		return RelayFrame{}, err
	}
	f.Sig = sig
	if _, err := parseRelayFrameValue(f.JSONValue()); err != nil {
		return RelayFrame{}, err
	}
	return f, nil
}

func parseAnyRelayFrame(frame any) (RelayFrame, error) {
	switch x := frame.(type) {
	case []byte:
		return ParseRelayFrame(x, RelayFrameOptions{})
	case RelayFrame:
		return parseRelayFrameValue(x.JSONValue())
	default:
		return parseRelayFrameValue(frame)
	}
}

func verifyRelayFrame(frame any, typ, context, signPub string) (RelayFrame, error) {
	f, err := parseAnyRelayFrame(frame)
	if err != nil {
		return RelayFrame{}, err
	}
	if f.Type != typ {
		return RelayFrame{}, badRequest("frame is not a %s frame", typ)
	}
	if err := VerifyObject(context, f, signPub); err != nil {
		return RelayFrame{}, err
	}
	return f, nil
}

// SignHello signs a hello frame (context akv1/relay) with the device's seed.
func SignHello(f RelayFrame, seed []byte) (RelayFrame, error) {
	return signRelayFrame(f, RelayHello, ContextRelay, seed)
}

// VerifyHelloOptions configures VerifyHello.
type VerifyHelloOptions struct {
	// SignPub is the b64 key named by the upgrade's AKV-Device-Key.
	SignPub string
	// Now is the server's unix ms clock.
	Now int64
	// MaxSkewMs defaults to ProofMaxSkewMs when zero.
	MaxSkewMs int64
}

// VerifyHello parses a hello frame (raw bytes, a RelayFrame or a parsed
// value) and checks, in order: device_id = kid(SignPub) (forbidden), the
// signature under SignPub (invalid_signature), |Now - ts| within the skew
// (unauthorized). The membership checks are the server's.
func VerifyHello(frame any, opts VerifyHelloOptions) (RelayFrame, error) {
	f, err := parseAnyRelayFrame(frame)
	if err != nil {
		return RelayFrame{}, err
	}
	if f.Type != RelayHello {
		return RelayFrame{}, badRequest("frame is not a hello frame")
	}
	if id, err := DeviceIDFromSignPubB64(opts.SignPub); err != nil || id != f.DeviceID {
		return RelayFrame{}, newErr(CodeForbidden, "hello device_id does not match the device key")
	}
	if err := VerifyObject(ContextRelay, f, opts.SignPub); err != nil {
		return RelayFrame{}, err
	}
	skew := opts.MaxSkewMs
	if skew == 0 {
		skew = ProofMaxSkewMs
	}
	if d := opts.Now - f.TS; d > skew || d < -skew {
		return RelayFrame{}, newErr(CodeUnauthorized, "hello outside the time window")
	}
	return f, nil
}

// SignResult signs a result frame (context akv1/relay-result).
func SignResult(f RelayFrame, seed []byte) (RelayFrame, error) {
	return signRelayFrame(f, RelayResult, ContextRelayResult, seed)
}

// VerifyResult parses a result frame and verifies its signature under the
// connection's device key signPub (b64); a result signed by another device
// is invalid_signature.
func VerifyResult(frame any, signPub string) (RelayFrame, error) {
	return verifyRelayFrame(frame, RelayResult, ContextRelayResult, signPub)
}
