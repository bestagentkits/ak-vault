package akv1

// DeviceKeys is a device's key material and its public device record.
type DeviceKeys struct {
	Record     DeviceRecord
	SignSecret []byte // Ed25519 seed
	KxSecret   []byte // X25519 secret
}

// CreateDeviceKeys generates device keys for account with role and kind
// (RoleOwner/RoleEditor/RoleReader, KindHuman/KindMachine). signSeed and
// kxSecret are nil in production (random); tests inject fixed secrets.
func CreateDeviceKeys(account, role, kind string, signSeed, kxSecret []byte) (DeviceKeys, error) {
	if signSeed == nil {
		signSeed = randomBytes(KeyBytes)
	}
	if kxSecret == nil {
		kxSecret = randomBytes(KeyBytes)
	}
	signPub, err := SignPublicKey(signSeed)
	if err != nil {
		return DeviceKeys{}, err
	}
	kxPub, err := KxPublicKey(kxSecret)
	if err != nil {
		return DeviceKeys{}, err
	}
	rec := DeviceRecord{DeviceID: Kid(signPub), SignPub: B64Encode(signPub), KxPub: B64Encode(kxPub), Account: account, Role: role, Kind: kind}
	if _, err := ParseDevice(rec); err != nil {
		return DeviceKeys{}, err
	}
	return DeviceKeys{Record: rec, SignSecret: signSeed, KxSecret: kxSecret}, nil
}
