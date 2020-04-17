package https_tpm




func (Loader) LoadCertificateFromNVRam(device string, handle uint32, password string) ([]byte, error) {
	panic("implement me")
}

func (Loader) WriteCertificateToNVRam(device string, cert []byte, handle uint32, password string) error {
	panic("implement me")
}

func (Loader) DeleteCertificateFromNVRam(device string, handle uint32, password string) error {
	panic("implement me")
}

