package https_tpm

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
)

func NewTransport(privateKey crypto.Signer, cert []byte) (*tls.Config, error) {

	// Check if certificate signature matches the private key
	if err := checkCertificate(cert, privateKey); err != nil {
		return nil, errors.Wrap(err, "certificate check failed")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{cert},
				PrivateKey:  privateKey,
			},
		},
	}, nil
}

// generateSelfSignCert will generate keys where specified
func generateSelfSignCert(priv crypto.Signer, host string) ([]byte, error) {

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

func checkCertificate(cert []byte, pk crypto.Signer) error {

	sCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return errors.Wrap(err, "couldn't load certificate")
	}

	if sCert.PublicKey.(*rsa.PublicKey).N.Cmp(pk.Public().(*rsa.PublicKey).N) == 0 && pk.Public().(*rsa.PublicKey).E == sCert.PublicKey.(*rsa.PublicKey).E {
		return nil
	}
	return errors.New("Public key don't match")
}
