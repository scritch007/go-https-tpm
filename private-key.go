package https_tpm

import (
	"crypto"
)

type PrivateKeyLoader interface{
	LoadPrivateKeyFromTPM(device string, handle uint32, password string) (crypto.Signer, error)
	GeneratePrivateKey(device string, handle uint32, password string)(crypto.Signer, error)
}
