package https_tpm

import (
	"github.com/folbricht/tpmk"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/pkg/errors"
)

type Loader struct{}

// LoadCertificateFromNVRam load the certificate from TPM NVRam
func (Loader) LoadCertificateFromNVRam(device string, handle uint32, password string) ([]byte, error) {
	dev, err := tpmk.OpenDevice(device)
	if err != nil {
		return nil, errors.Wrap(err, "opening TPM")
	}

	defer dev.Close()

	return tpmk.NVRead(dev, tpmutil.Handle(handle), password)
}

// WriteCertificateToNVRam helper to store certificate to NVRam
func (Loader) WriteCertificateToNVRam(device string, cert []byte, handle uint32, password string) error {
	dev, err := tpmk.OpenDevice(device)
	if err != nil {
		return errors.Wrap(err, "opening TPM")
	}

	defer dev.Close()

	return tpmk.NVWrite(dev,
		tpmutil.Handle(handle),
		cert,
		password,
		tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead|tpm2.AttrAuthRead|tpm2.AttrPPRead)
}

// DeleteCertificateFromNVRam helper to delete entry from NVRam
func (Loader) DeleteCertificateFromNVRam(device string, handle uint32, password string) error {
	dev, err := tpmk.OpenDevice(device)
	if err != nil {
		return errors.Wrap(err, "opening TPM")
	}

	defer dev.Close()

	return tpmk.NVDelete(dev,
		tpmutil.Handle(handle),
		password)
}
