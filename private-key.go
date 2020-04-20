package https_tpm

import (
	"crypto"
	"crypto/rsa"
)

type PrivateKeyLoader interface {
	LoadPrivateKeyFromTPM(device string, handle uint32, password string) (crypto.Signer, error)
	GeneratePrivateKey(device string, handle uint32, password string) (crypto.Signer, error)
	StorePrivateKey(device string, handle uint32, password string, key *rsa.PrivateKey) error
}
