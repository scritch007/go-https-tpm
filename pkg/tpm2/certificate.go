package https_tpm

import (
	"github.com/chrisccoulson/go-tpm2"
	"github.com/pkg/errors"
)

func (Loader) LoadCertificateFromNVRam(device string, handle uint32, password string) ([]byte, error) {
	dev, err := openTPM(device)
	if dev != nil {
		defer dev.Close()
	}

	if err != nil {
		return nil, errors.Wrap(err, "couldn't open TPM")
	}

	certHandle, err := dev.CreateResourceContextFromTPM(tpm2.Handle(handle))
	if err != nil {
		return nil, errors.Wrap(err, "couldn't get resource")
	}

	// We can put what ever we want in the size it will be narrowed to maxNV size
	pub, _, err := dev.NVReadPublic(certHandle)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't read public from NV")
	}

	buff, err := dev.NVRead(dev.OwnerHandleContext(), certHandle, pub.Size, 0, nil)

	if err != nil {
		return nil, errors.Wrap(err, "couldn't read from NV")
	}

	return buff, nil
}

func (Loader) WriteCertificateToNVRam(device string, cert []byte, handle uint32, password string) error {
	panic("implement me")
}

func (Loader) DeleteCertificateFromNVRam(device string, handle uint32, password string) error {
	panic("implement me")
}
