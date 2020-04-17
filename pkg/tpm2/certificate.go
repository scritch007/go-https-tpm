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
	dev, err := openTPM(device)
	if dev != nil {
		defer dev.Close()
	}

	if err != nil {
		return errors.Wrap(err, "couldn't open TPM")
	}
	pub := tpm2.NVPublic{
		Index:   tpm2.Handle(handle),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerWrite|tpm2.AttrNVOwnerRead|tpm2.AttrNVAuthRead|tpm2.AttrNVPolicyRead),
		Size:    uint16(len(cert))}
	rc, err := dev.NVDefineSpace(dev.OwnerHandleContext(), nil, &pub, nil)
	if err != nil {
		return errors.Wrap(err, "couldn't define new NV space")
	}

	return errors.Wrap(dev.NVWrite(dev.OwnerHandleContext(), rc, cert, 0, nil),
		"couldn't create handle")
}

func (Loader) DeleteCertificateFromNVRam(device string, handle uint32, password string) error {
	dev, err := openTPM(device)
	if dev != nil {
		defer dev.Close()
	}

	if err != nil {
		return errors.Wrap(err, "couldn't open TPM")
	}

	certHandle, err := dev.CreateResourceContextFromTPM(tpm2.Handle(handle))
	if err != nil {
		return errors.Wrap(err, "couldn't get resource")
	}

	return errors.Wrap(dev.NVUndefineSpace(dev.OwnerHandleContext(), certHandle, nil),
		"couldn't delete certificate")
}
