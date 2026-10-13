package akv1

// Closed value sets of the membership log (spec §4).
const (
	RoleOwner  = "owner"
	RoleEditor = "editor"
	RoleReader = "reader"

	KindHuman   = "human"
	KindMachine = "machine"

	VaultPersonal = "personal"
	VaultShared   = "shared"
	VaultCI       = "ci"

	EventGenesis      = "genesis"
	EventDeviceAdd    = "device_add"
	EventDeviceRemove = "device_remove"
	EventMemberAdd    = "member_add"
	EventMemberRemove = "member_remove"
	EventRoleSet      = "role_set"
	EventRekey        = "rekey"
)

var (
	roles             = []string{RoleOwner, RoleEditor, RoleReader}
	deviceKinds       = []string{KindHuman, KindMachine}
	vaultKinds        = []string{VaultPersonal, VaultShared, VaultCI}
	removeReasons     = []string{"lost", "stolen", "retired", "compromised"}
	membershipEvTypes = []string{EventGenesis, EventDeviceAdd, EventDeviceRemove, EventMemberAdd, EventMemberRemove, EventRoleSet, EventRekey}
)

// MaxAccountLength bounds account identifiers (UTF-16 code units).
const MaxAccountLength = 256

// DeviceRecord is {"device_id","sign_pub","kx_pub","account","role","kind"}.
type DeviceRecord struct {
	DeviceID string
	SignPub  string
	KxPub    string
	Account  string
	Role     string
	Kind     string
}

// JSONValue returns the wire object.
func (d DeviceRecord) JSONValue() any {
	return map[string]any{"device_id": d.DeviceID, "sign_pub": d.SignPub, "kx_pub": d.KxPub, "account": d.Account, "role": d.Role, "kind": d.Kind}
}

// MembershipEvent is one owner-signed, hash-chained membership event.
type MembershipEvent struct {
	Type            string
	VaultID         string
	Seq             int64
	Prev            string
	MembershipEpoch int64
	KeyEpoch        int64
	TS              int64
	Author          string
	Body            map[string]any
	Sig             string // empty for an unsigned event
}

// JSONValue returns the wire object ("sig" omitted when empty).
func (e MembershipEvent) JSONValue() any {
	m := map[string]any{
		"v": int64(1), "type": e.Type, "vault_id": e.VaultID, "seq": e.Seq, "prev": e.Prev,
		"membership_epoch": e.MembershipEpoch, "key_epoch": e.KeyEpoch, "ts": e.TS, "author": e.Author, "body": e.Body,
	}
	if e.Sig != "" {
		m["sig"] = e.Sig
	}
	return m
}

// Member is an account and its role.
type Member struct {
	Account string
	Role    string
}

// MembershipState is the vault membership derived by replaying a verified
// chain. Slices are sorted by key (members by account, devices by device_id).
type MembershipState struct {
	VaultID          string
	VaultKind        string
	OwnerAccount     string
	TrustAnchor      string // b64 sign_pub of the genesis author (pinned anchor)
	RecoverySignPub  string // b64 owner recovery signing public key (§3.5)
	RecoveryAuthor   string // kid(recovery_sign_pub)
	Seq              int64
	Head             string // hash of the last event (the next event's prev)
	MembershipEpoch  int64
	KeyEpoch         int64
	RekeyRequired    bool
	NeedsRotate      []string
	WrapsDigest      string // "" before the first rekey (JSON null)
	Members          []Member
	Devices          []DeviceRecord
	RemovedDeviceIDs []string
}

// JSONValue returns the state in the same JSON shape as the TypeScript reference.
func (s MembershipState) JSONValue() any {
	members := make([]any, len(s.Members))
	for i, m := range s.Members {
		members[i] = map[string]any{"account": m.Account, "role": m.Role}
	}
	devices := make([]any, len(s.Devices))
	for i, d := range s.Devices {
		devices[i] = d.JSONValue()
	}
	var wd any
	if s.WrapsDigest != "" {
		wd = s.WrapsDigest
	}
	return map[string]any{
		"vault_id": s.VaultID, "vault_kind": s.VaultKind, "owner_account": s.OwnerAccount,
		"trust_anchor": s.TrustAnchor, "recovery_sign_pub": s.RecoverySignPub, "recovery_author": s.RecoveryAuthor,
		"seq": s.Seq, "head": s.Head, "membership_epoch": s.MembershipEpoch, "key_epoch": s.KeyEpoch,
		"rekey_required": s.RekeyRequired, "needs_rotate": stringsToAny(s.NeedsRotate), "wraps_digest": wd,
		"members": members, "devices": devices, "removed_device_ids": stringsToAny(s.RemovedDeviceIDs),
	}
}

// FindDevice returns the current device with deviceID.
func (s MembershipState) FindDevice(deviceID string) (DeviceRecord, bool) {
	for _, d := range s.Devices {
		if d.DeviceID == deviceID {
			return d, true
		}
	}
	return DeviceRecord{}, false
}

// ParseDevice validates an untrusted device record, including device_id == kid(sign_pub).
func ParseDevice(v any) (DeviceRecord, error) { return parseDeviceAs(v, "device") }

func parseDeviceAs(v any, what string) (DeviceRecord, error) {
	obj, err := asObject(v, what)
	if err != nil {
		return DeviceRecord{}, err
	}
	if err := exactKeys(obj, []string{"device_id", "sign_pub", "kx_pub", "account", "role", "kind"}, what); err != nil {
		return DeviceRecord{}, err
	}
	var d DeviceRecord
	if d.DeviceID, err = asID(obj["device_id"], what+".device_id"); err != nil {
		return DeviceRecord{}, err
	}
	if d.SignPub, err = asB64(obj["sign_pub"], what+".sign_pub", KeyBytes); err != nil {
		return DeviceRecord{}, err
	}
	if d.KxPub, err = asB64(obj["kx_pub"], what+".kx_pub", KeyBytes); err != nil {
		return DeviceRecord{}, err
	}
	if d.Account, err = asString(obj["account"], what+".account", MaxAccountLength, 1); err != nil {
		return DeviceRecord{}, err
	}
	if d.Role, err = asEnum(obj["role"], roles, what+".role"); err != nil {
		return DeviceRecord{}, err
	}
	if d.Kind, err = asEnum(obj["kind"], deviceKinds, what+".kind"); err != nil {
		return DeviceRecord{}, err
	}
	id, err := DeviceIDFromSignPubB64(d.SignPub)
	if err != nil {
		return DeviceRecord{}, err
	}
	if id != d.DeviceID {
		return DeviceRecord{}, badRequest("%s.device_id does not match sign_pub", what)
	}
	return d, nil
}

// ParseMembershipEvent structurally validates one event (signature and chain
// rules are checked by VerifyMembershipChain).
func ParseMembershipEvent(v any) (MembershipEvent, error) {
	return parseMembershipEventAs(v, "membership event")
}

func parseMembershipEventAs(v any, what string) (MembershipEvent, error) {
	obj, err := asObject(v, what)
	if err != nil {
		return MembershipEvent{}, err
	}
	if err := checkVersion(obj, what); err != nil {
		return MembershipEvent{}, err
	}
	typ, ok := obj["type"].(string)
	if !ok || !contains(membershipEvTypes, typ) {
		return MembershipEvent{}, newErr(CodeUnsupportedVersion, "%s: unsupported event type", what)
	}
	if err := exactKeys(obj, []string{"v", "type", "vault_id", "seq", "prev", "membership_epoch", "key_epoch", "ts", "author", "body", "sig"}, what); err != nil {
		return MembershipEvent{}, err
	}
	e := MembershipEvent{Type: typ}
	if obj["prev"] != "" {
		if e.Prev, err = asB64(obj["prev"], what+".prev", 32); err != nil {
			return MembershipEvent{}, err
		}
	}
	if e.VaultID, err = asID(obj["vault_id"], what+".vault_id"); err != nil {
		return MembershipEvent{}, err
	}
	if e.Seq, err = asUint(obj["seq"], what+".seq"); err != nil {
		return MembershipEvent{}, err
	}
	if e.MembershipEpoch, err = asUint(obj["membership_epoch"], what+".membership_epoch"); err != nil {
		return MembershipEvent{}, err
	}
	if e.KeyEpoch, err = asInt(obj["key_epoch"], what+".key_epoch", 1, MaxSafeInteger); err != nil {
		return MembershipEvent{}, err
	}
	if e.TS, err = asUint(obj["ts"], what+".ts"); err != nil {
		return MembershipEvent{}, err
	}
	if e.Author, err = asID(obj["author"], what+".author"); err != nil {
		return MembershipEvent{}, err
	}
	if e.Body, err = asObject(obj["body"], what+".body"); err != nil {
		return MembershipEvent{}, err
	}
	if e.Sig, err = asB64(obj["sig"], what+".sig", 64); err != nil {
		return MembershipEvent{}, err
	}
	return e, nil
}
