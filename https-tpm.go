package https_tpm

import (
	"crypto"
	"fmt"
	"github.com/folbricht/tpmk"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"runtime"
	"sync"

	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type wrapper struct {
	device    string
	handle    tpmutil.Handle
	publicKey crypto.PublicKey
	lock      sync.Mutex
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

	pk, err = tpmk.NewRSAPrivateKey(dev, w.handle, "")
	if err != nil {
		return pk, cw, errors.Wrap(err, "error loading private key")
	}

	return pk, cw, nil
}

func NewTransport(device string, handle, certificateHandle tpmutil.Handle, hostname string) (*tls.Config, error) {

	w := &wrapper{
		device: device,
		handle: handle,
	}

	pk, tpmClose, err := w.getPk()
	defer tpmClose.Close()
	if err != nil {
		return nil, errors.Wrap(err, "retrieve private key")
	}

	w.publicKey = pk.Public()
	var cert []byte

	cert, err = tpmk.NVRead(tpmClose, certificateHandle, "")

	if err != nil {
		fmt.Printf("Couldn't access to certificate: %v regenerating", err)
		cert, err := generateSelfSignCert(&pk, hostname)
		if err != nil {
			return nil, errors.Wrap(err, "couldn't generate certificate")
		}

		if err = tpmk.NVWrite(tpmClose,
			certificateHandle,
			cert,
			"",
			tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead|tpm2.AttrAuthRead|tpm2.AttrPPRead); err != nil {
			return nil, errors.Wrap(err, "couldn't write to NV")
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert},
				PrivateKey:  w,
			},
		},
	}, nil
}

// generateSelfSignCert will generate keys where specified
func generateSelfSignCert(priv *tpmk.RSAPrivateKey, host string) ([]byte, error) {

	notBefore := time.Now()

	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %s", err)
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split(host, ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't create self signed certificate")
	}

	return derBytes, nil
}
