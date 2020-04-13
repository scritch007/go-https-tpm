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

func NewTransport(privateKey crypto.PrivateKey, cert []byte) (*tls.Config, error) {

	// Check if certificate signature matches the private key

	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert},
				PrivateKey:  privateKey,
			},
		},
	}, nil
}

type privateKey interface {
	Public() crypto.PublicKey
}

// generateSelfSignCert will generate keys where specified
func generateSelfSignCert(priv privateKey, host string) ([]byte, error) {

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

// LoadPrivateKeyFromTPM return a private from TPM
func LoadPrivateKeyFromTPM(device string, handle tpmutil.Handle, password string) (crypto.PrivateKey, error) {

	w := &wrapper{
		device:   device,
		handle:   handle,
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
func GenerateSelfSignCertificate(pk crypto.PrivateKey, hostname string) ([]byte, error) {

	privateKey, ok := pk.(privateKey)
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
