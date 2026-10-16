module github.com/bestagentkits/ak-vault/e2e/docker/fake-akweb

go 1.24.0

require github.com/bestagentkits/ak-vault/go v0.0.0

require (
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
)

// The protocol module from this checkout, so the fake signs and verifies
// with exactly the akv1 code under test.
replace github.com/bestagentkits/ak-vault/go => ../../../go
