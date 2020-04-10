package https_tpm

import (
	"crypto"
	"github.com/folbricht/tpmk"
	"github.com/google/go-tpm/tpmutil"

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
}

func (w wrapper) Public() crypto.PublicKey {
	return w.publicKey
}
func (w wrapper) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	pk, close, err := w.getPk()
	defer close()
	if err != nil {
		return nil, errors.Wrap(err, "Sign: retrieving private key")
	}
	return pk.Sign(rand, digest, opts)
}

func (w wrapper) getPk() (*tpmk.RSAPrivateKey, func() error, error) {
	dev, err := tpmk.OpenDevice(w.device)
	if err != nil {
		return nil, func() error { return nil }, errors.Wrapf(err, "opening %s", w.device)
	}

	pk, err := tpmk.NewRSAPrivateKey(dev, w.handle, "")
	if err != nil {
		return nil, dev.Close, errors.Wrap(err, "error loading private key")
	}

	return &pk, dev.Close, nil
}

func NewTransport(device string, handle tpmutil.Handle, hostname string) (*tls.Config, error) {

	w := wrapper{
		device: device,
		handle: handle,
	}

	pk, tpmClose, err := w.getPk()
	defer tpmClose()
	if err != nil {
		return nil, errors.Wrap(err, "retrieve private key")
	}

	w.publicKey = pk.Public()

	cert, err := generateSelfSignCert(pk, hostname)
	if err != nil {
		return nil, errors.Wrap(err, "couldn't generate certificate")
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
