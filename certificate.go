package https_tpm

import (
	"crypto"
	"github.com/folbricht/tpmk"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/pkg/errors"
)

// LoadCertificateFromNVRam load the certificate from TPM NVRam
func LoadCertificateFromNVRam(device string, handle tpmutil.Handle, password string) ([]byte, error) {
	dev, err := tpmk.OpenDevice(device)
	if err != nil {
		return nil, errors.Wrap(err, "opening TPM")
	}

	defer dev.Close()

	return tpmk.NVRead(dev, handle, password)
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

// WriteCertificateToNVRam helper to store certificate to NVRam
func WriteCertificateToNVRam(device string, cert []byte, handle tpmutil.Handle, password string) error {
	dev, err := tpmk.OpenDevice(device)
	if err != nil {
		return errors.Wrap(err, "opening TPM")
	}

	defer dev.Close()

	return tpmk.NVWrite(dev,
		handle,
		cert,
		password,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead|tpm2.AttrAuthRead|tpm2.AttrPPRead)
}

// DeleteCertificateFromNVRam helper to delete entry from NVRam
func DeleteCertificateFromNVRam(device string, handle tpmutil.Handle, password string) error {
	dev, err := tpmk.OpenDevice(device)
	if err != nil {
		return errors.Wrap(err, "opening TPM")
	}

	defer dev.Close()

	return tpmk.NVDelete(dev,
		handle,
		password)
}
