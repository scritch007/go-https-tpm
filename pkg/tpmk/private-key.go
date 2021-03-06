package https_tpm

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"github.com/folbricht/tpmk"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/pkg/errors"
	"io"
	"runtime"
	"sync"
)

// LoadPrivateKeyFromTPM return a private from TPM
func (Loader) LoadPrivateKeyFromTPM(device string, handle uint32, password string) (crypto.Signer, error) {

	w := &wrapper{
		device:   device,
		handle:   tpmutil.Handle(handle),
		password: password,
	}

	pk, tpmClose, err := w.getPk()
	defer tpmClose.Close()
	if err != nil {
		return nil, errors.Wrap(err, "retrieve private key")
	}

	w.publicKey = pk.Public()

	return w, nil
}

type wrapper struct {
	device    string
	handle    tpmutil.Handle
	publicKey crypto.PublicKey
	lock      sync.Mutex
	password  string
}

func (w *wrapper) Public() crypto.PublicKey {
	return w.publicKey
}

func (w *wrapper) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	pk, close, err := w.getPk()
	defer close.Close()
	if err != nil {
		return nil, errors.Wrap(err, "Sign: retrieving private key")
	}
	return pk.Sign(rand, digest, opts)
}

type closeWrapper struct {
	close func() error
	dev   io.ReadWriter
}

func (c closeWrapper) Read(p []byte) (n int, err error) {
	return c.dev.Read(p)
}

func (c closeWrapper) Write(p []byte) (n int, err error) {
	return c.dev.Write(p)
}

func (c closeWrapper) Close() error {
	return c.close()
}

func (w *wrapper) getPk() (pk tpmk.RSAPrivateKey, cw io.ReadWriteCloser, err error) {
	w.lock.Lock()
	_, file, no, ok := runtime.Caller(1)
	if ok {
		fmt.Printf("called from %s#%d\n", file, no)
	}

	dev, err := tpmk.OpenDevice(w.device)
	if err != nil {
		return pk, closeWrapper{close: func() error { return nil }}, errors.Wrapf(err, "opening %s", w.device)
	}

	cw = closeWrapper{
		dev: dev,
		close: func() error {
			fmt.Println("TPM closed")
			err := dev.Close()
			w.lock.Unlock()
			return err
		},
	}

	pk, err = tpmk.NewRSAPrivateKey(dev, w.handle, w.password)
	if err != nil {
		return pk, cw, errors.Wrap(err, "error loading private key")
	}

	return pk, cw, nil
}

func (l Loader) GeneratePrivateKey(device string, handle uint32, password string) (crypto.Signer, error) {
	iow, err := tpmk.OpenDevice(device)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't open TPM")
	}
	_, err = tpmk.GenRSAPrimaryKey(iow, tpmutil.Handle(handle), "", password, tpm2.FlagSign|tpm2.FlagDecrypt|tpm2.FlagUserWithAuth|tpm2.FlagSensitiveDataOrigin)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't create key")
	}
	iow.Close()
	return l.LoadPrivateKeyFromTPM(device, handle, password)
}

func (l Loader) StorePrivateKey(device string, handle uint32, password string, key *rsa.PrivateKey) error {
	return errors.New("not implemented")
}
