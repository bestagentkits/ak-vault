package akv1

import (
	"sort"
	"unicode/utf16"
)

// replayState is the mutable state of a membership chain replay (spec §4,
// §11). The public entry point is VerifyMembershipChain.
type replayState struct {
	vaultKind       string
	ownerAccount    string
	trustAnchor     string
	recoverySignPub string
	recoveryAuthor  string
	keyEpoch        int64
	rekeyRequired   bool
	wrapsDigest     string
	needsRotate     map[string]bool
	members         map[string]string // account -> role
	devices         map[string]DeviceRecord
	removed         map[string]bool
	removals        []DeviceRemoval
	// recoveryAuthors holds every recovery author ID the chain has ever trusted.
	recoveryAuthors map[string]bool
}

func newReplayState() *replayState {
	return &replayState{
		vaultKind: VaultPersonal, keyEpoch: 1,
		needsRotate: map[string]bool{}, members: map[string]string{},
		devices: map[string]DeviceRecord{}, removed: map[string]bool{},
		recoveryAuthors: map[string]bool{},
	}
}

func (r *replayState) ownerDeviceCount() int {
	n := 0
	for _, d := range r.devices {
		if d.Role == RoleOwner && d.Kind == KindHuman {
			n++
		}
	}
	return n
}

func (r *replayState) ownerAccountCount() int {
	n := 0
	for _, role := range r.members {
		if role == RoleOwner {
			n++
		}
	}
	return n
}

// admitDevice adds a device; a previously removed ID needs allowReadd (a fresh device_add).
func (r *replayState) admitDevice(d DeviceRecord, allowReadd bool) error {
	if _, ok := r.devices[d.DeviceID]; ok {
		return badRequest("device is already a member")
	}
	if r.recoveryAuthors[d.DeviceID] {
		return badRequest("device key collides with a recovery key")
	}
	if r.removed[d.DeviceID] {
		if !allowReadd {
			return newErr(CodeForbidden, "removed device reappears without a fresh device_add")
		}
		delete(r.removed, d.DeviceID)
	}
	r.devices[d.DeviceID] = d
	return nil
}

// recordRemoval records a removal; the caller has already deleted the device from devices.
func (r *replayState) recordRemoval(d DeviceRecord, seq int64, fence ChangeLogCursor) {
	r.removed[d.DeviceID] = true
	r.removals = append(r.removals, DeviceRemoval{DeviceID: d.DeviceID, SignPub: d.SignPub, RemovedSeq: seq, KeyEpoch: r.keyEpoch, LogFence: fence.LogSeq, LogHead: fence.LogHead})
}

func parseDeviceList(v any, what string) ([]DeviceRecord, error) {
	arr, err := asArray(v, what, 64)
	if err != nil {
		return nil, err
	}
	out := make([]DeviceRecord, 0, len(arr))
	for _, item := range arr {
		d, err := parseDeviceAs(item, what+"[]")
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func (r *replayState) applyGenesis(body map[string]any, author string) (DeviceRecord, error) {
	var err error
	if err = exactKeys(body, []string{"vault_kind", "owner_account", "recovery_sign_pub", "devices", "wraps_digest"}, "genesis.body"); err != nil {
		return DeviceRecord{}, err
	}
	if _, err = asB64(body["wraps_digest"], "genesis.body.wraps_digest", 32); err != nil {
		return DeviceRecord{}, err
	}
	if r.vaultKind, err = asEnum(body["vault_kind"], vaultKinds, "genesis.body.vault_kind"); err != nil {
		return DeviceRecord{}, err
	}
	if r.ownerAccount, err = asString(body["owner_account"], "genesis.body.owner_account", MaxAccountLength, 1); err != nil {
		return DeviceRecord{}, err
	}
	if r.recoverySignPub, err = asB64(body["recovery_sign_pub"], "genesis.body.recovery_sign_pub", KeyBytes); err != nil {
		return DeviceRecord{}, err
	}
	if r.recoveryAuthor, err = DeviceIDFromSignPubB64(r.recoverySignPub); err != nil {
		return DeviceRecord{}, err
	}
	r.recoveryAuthors[r.recoveryAuthor] = true
	devices, err := parseDeviceList(body["devices"], "genesis.body.devices")
	if err != nil {
		return DeviceRecord{}, err
	}
	if len(devices) == 0 {
		return DeviceRecord{}, badRequest("genesis needs at least one device")
	}
	r.members[r.ownerAccount] = RoleOwner
	for _, d := range devices {
		if d.Account != r.ownerAccount || d.Role != RoleOwner {
			return DeviceRecord{}, badRequest("genesis devices must be owner devices of owner_account")
		}
		if err := r.admitDevice(d, false); err != nil {
			return DeviceRecord{}, err
		}
	}
	authorDevice, ok := r.devices[author]
	if !ok || authorDevice.Kind != KindHuman {
		return DeviceRecord{}, newErr(CodeForbidden, "genesis author must be a human owner device in genesis")
	}
	r.trustAnchor = authorDevice.SignPub
	return authorDevice, nil
}

// authorKey resolves the b64 signing key of a non-genesis author, enforcing
// who may author the event type.
func (r *replayState) authorKey(e MembershipEvent) (string, error) {
	if e.Author == r.recoveryAuthor {
		// The recovery identity cannot read the change log, so it cannot sign an
		// honest removal fence: it only enrolls a device, which then removes lost ones.
		if e.Type != EventDeviceAdd {
			return "", newErr(CodeForbidden, "recovery key may only author device_add")
		}
		return r.recoverySignPub, nil
	}
	d, ok := r.devices[e.Author]
	if !ok {
		return "", newErr(CodeForbidden, "author is not a current device")
	}
	if d.Role != RoleOwner || d.Kind != KindHuman {
		return "", newErr(CodeForbidden, "author is not a human owner device")
	}
	return d.SignPub, nil
}

func (r *replayState) apply(e MembershipEvent) error {
	body := e.Body
	byRecovery := e.Author == r.recoveryAuthor
	switch e.Type {
	case EventDeviceAdd:
		return r.applyDeviceAdd(body, byRecovery)
	case EventDeviceRemove:
		if err := exactKeys(body, []string{"device_id", "reason", "log_fence", "log_head"}, "device_remove.body"); err != nil {
			return err
		}
		id, err := asID(body["device_id"], "device_remove.body.device_id")
		if err != nil {
			return err
		}
		if _, err := asEnum(body["reason"], removeReasons, "device_remove.body.reason"); err != nil {
			return err
		}
		logFence, err := ParseLogPosition(body["log_fence"], body["log_head"], "device_remove.body.log_fence", "device_remove.body.log_head")
		if err != nil {
			return err
		}
		removed, ok := r.devices[id]
		if !ok {
			return badRequest("device is not a current member")
		}
		delete(r.devices, id)
		r.recordRemoval(removed, e.Seq, logFence)
		if r.ownerDeviceCount() == 0 {
			return newErr(CodeForbidden, "cannot remove the last human owner device")
		}
		r.rekeyRequired = true
		return nil
	case EventMemberAdd:
		return r.applyMemberAdd(body)
	case EventMemberRemove:
		if err := exactKeys(body, []string{"account", "log_fence", "log_head"}, "member_remove.body"); err != nil {
			return err
		}
		if r.vaultKind != VaultShared {
			return newErr(CodeForbidden, "member_remove is only allowed in shared vaults")
		}
		account, err := asString(body["account"], "member_remove.body.account", MaxAccountLength, 1)
		if err != nil {
			return err
		}
		logFence, err := ParseLogPosition(body["log_fence"], body["log_head"], "member_remove.body.log_fence", "member_remove.body.log_head")
		if err != nil {
			return err
		}
		if _, ok := r.members[account]; !ok {
			return badRequest("account is not a member")
		}
		delete(r.members, account)
		leaving := make([]DeviceRecord, 0)
		for _, d := range r.devices {
			if d.Account == account {
				leaving = append(leaving, d)
			}
		}
		sort.Slice(leaving, func(i, j int) bool { return utf16Less(leaving[i].DeviceID, leaving[j].DeviceID) })
		for _, d := range leaving {
			delete(r.devices, d.DeviceID)
			r.recordRemoval(d, e.Seq, logFence)
		}
		if r.ownerAccountCount() == 0 || r.ownerDeviceCount() == 0 {
			return newErr(CodeForbidden, "cannot remove the last owner")
		}
		r.rekeyRequired = true
		return nil
	case EventRoleSet:
		if err := exactKeys(body, []string{"account", "role"}, "role_set.body"); err != nil {
			return err
		}
		account, err := asString(body["account"], "role_set.body.account", MaxAccountLength, 1)
		if err != nil {
			return err
		}
		role, err := asEnum(body["role"], roles, "role_set.body.role")
		if err != nil {
			return err
		}
		if _, ok := r.members[account]; !ok {
			return badRequest("account is not a member")
		}
		r.members[account] = role
		for id, d := range r.devices {
			if d.Account == account {
				d.Role = role
				r.devices[id] = d
			}
		}
		if r.ownerAccountCount() == 0 || r.ownerDeviceCount() == 0 {
			return newErr(CodeForbidden, "cannot demote the last owner")
		}
		return nil
	case EventRekey:
		return r.applyRekey(e)
	case EventRecoveryRotate:
		return r.applyRecoveryRotate(body)
	default: // genesis after seq 0
		return badRequest("genesis must be the first event only")
	}
}

func (r *replayState) applyDeviceAdd(body map[string]any, byRecovery bool) error {
	if err := exactKeys(body, []string{"device", "sas", "wraps_digest"}, "device_add.body"); err != nil {
		return err
	}
	if _, err := asB64(body["wraps_digest"], "device_add.body.wraps_digest", 32); err != nil {
		return err
	}
	d, err := parseDeviceAs(body["device"], "device_add.body.device")
	if err != nil {
		return err
	}
	if byRecovery {
		if body["sas"] != "" {
			return badRequest(`recovery-authored device_add must carry sas ""`)
		}
		if d.Role != RoleOwner {
			return newErr(CodeForbidden, "recovery key may only add owner devices")
		}
	} else if _, err := asB64(body["sas"], "device_add.body.sas", 32); err != nil {
		return err
	}
	accountRole, ok := r.members[d.Account]
	if !ok {
		return newErr(CodeForbidden, "device account is not a member")
	}
	if accountRole != d.Role {
		return badRequest("device role must equal its account role")
	}
	return r.admitDevice(d, true)
}

func (r *replayState) applyMemberAdd(body map[string]any) error {
	if err := exactKeys(body, []string{"account", "role", "devices", "wraps_digest"}, "member_add.body"); err != nil {
		return err
	}
	if _, err := asB64(body["wraps_digest"], "member_add.body.wraps_digest", 32); err != nil {
		return err
	}
	if r.vaultKind != VaultShared {
		return newErr(CodeForbidden, "member_add is only allowed in shared vaults")
	}
	account, err := asString(body["account"], "member_add.body.account", MaxAccountLength, 1)
	if err != nil {
		return err
	}
	role, err := asEnum(body["role"], roles, "member_add.body.role")
	if err != nil {
		return err
	}
	if _, ok := r.members[account]; ok {
		return badRequest("account is already a member")
	}
	devices, err := parseDeviceList(body["devices"], "member_add.body.devices")
	if err != nil {
		return err
	}
	if len(devices) == 0 {
		return badRequest("member_add needs at least one device")
	}
	r.members[account] = role
	for _, d := range devices {
		if d.Account != account || d.Role != role {
			return badRequest("member device account/role mismatch")
		}
		if err := r.admitDevice(d, false); err != nil {
			return err
		}
	}
	return nil
}

func (r *replayState) applyRekey(e MembershipEvent) error {
	body := e.Body
	if err := exactKeys(body, []string{"new_key_epoch", "wraps_digest", "needs_rotate"}, "rekey.body"); err != nil {
		return err
	}
	next, err := asInt(body["new_key_epoch"], "rekey.body.new_key_epoch", 1, MaxSafeInteger)
	if err != nil {
		return err
	}
	if next != r.keyEpoch+1 || e.KeyEpoch != next {
		return badRequest("rekey must advance key_epoch by exactly 1")
	}
	if r.wrapsDigest, err = asB64(body["wraps_digest"], "rekey.body.wraps_digest", 32); err != nil {
		return err
	}
	ids, err := asIDList(body["needs_rotate"], "rekey.body.needs_rotate", 100000)
	if err != nil {
		return err
	}
	for _, id := range ids {
		r.needsRotate[id] = true
	}
	r.keyEpoch = next
	r.rekeyRequired = false
	return nil
}

// applyRecoveryRotate replaces the recovery key with one never trusted before
// that does not collide with a current or former device key.
func (r *replayState) applyRecoveryRotate(body map[string]any) error {
	if err := exactKeys(body, []string{"recovery_sign_pub"}, "recovery_rotate.body"); err != nil {
		return err
	}
	pub, err := asB64(body["recovery_sign_pub"], "recovery_rotate.body.recovery_sign_pub", KeyBytes)
	if err != nil {
		return err
	}
	author, err := DeviceIDFromSignPubB64(pub)
	if err != nil {
		return err
	}
	if r.recoveryAuthors[author] {
		return badRequest("recovery_rotate must move to a recovery key never used before")
	}
	if _, ok := r.devices[author]; ok {
		return badRequest("recovery key collides with a device key")
	}
	for _, rm := range r.removals {
		if rm.DeviceID == author {
			return badRequest("recovery key collides with a device key")
		}
	}
	r.recoverySignPub = pub
	r.recoveryAuthor = author
	r.recoveryAuthors[author] = true
	return nil
}

// utf16Less orders strings like JavaScript's default string comparison
// (UTF-16 code units), which differs from byte order only for text mixing
// supplementary-plane and U+E000..U+FFFF characters.
func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return utf16Less(out[i], out[j]) })
	return out
}

func (r *replayState) snapshot(vaultID string, seq int64, head string) MembershipState {
	members := make([]Member, 0, len(r.members))
	for account, role := range r.members {
		members = append(members, Member{Account: account, Role: role})
	}
	sort.Slice(members, func(i, j int) bool { return utf16Less(members[i].Account, members[j].Account) })
	devices := make([]DeviceRecord, 0, len(r.devices))
	for _, d := range r.devices {
		devices = append(devices, d)
	}
	sort.Slice(devices, func(i, j int) bool { return utf16Less(devices[i].DeviceID, devices[j].DeviceID) })
	return MembershipState{
		VaultID: vaultID, VaultKind: r.vaultKind, OwnerAccount: r.ownerAccount,
		TrustAnchor: r.trustAnchor, RecoverySignPub: r.recoverySignPub, RecoveryAuthor: r.recoveryAuthor,
		Seq: seq, Head: head, MembershipEpoch: seq, KeyEpoch: r.keyEpoch, RekeyRequired: r.rekeyRequired,
		NeedsRotate: sortedKeys(r.needsRotate), WrapsDigest: r.wrapsDigest,
		Members: members, Devices: devices, RemovedDeviceIDs: sortedKeys(r.removed),
		Removals: append([]DeviceRemoval(nil), r.removals...),
	}
}
