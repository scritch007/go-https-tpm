package https_tpm

import (
	"crypto"
	"github.com/pkg/errors"
)

type CertificateLoader interface {
	LoadCertificateFromNVRam(device string, handle uint32, password string) ([]byte, error)
	WriteCertificateToNVRam(device string, cert []byte, handle uint32, password string) error
	DeleteCertificateFromNVRam(device string, handle uint32, password string) error
}

// Generate a self signed certificate
func GenerateSelfSignCertificate(pk crypto.Signer, hostname string) ([]byte, error) {

	privateKey, ok := pk.(crypto.Signer)
	if !ok {
		return nil, errors.New("Private key doesn't have Public method")
	}

	cert, err := generateSelfSignCert(privateKey, hostname)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't generate certificate")
	}
	return cert, nil
}
