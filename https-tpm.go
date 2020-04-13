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

func NewTransport(privateKey crypto.PrivateKey, cert []byte) (*tls.Config, error) {

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

func checkCertificate(cert []byte, pk crypto.PrivateKey) error {

	sCert, err := x509.ParseCertificate(cert)

	switch pk.(type) {
	case privateKey:
		switch pk.(privateKey).Public().(type) {
		case *rsa.PublicKey:
		default:
			return errors.New("unimplemented public key type")
		}
		err = checkSignature(sCert, sCert.Signature, pk.(privateKey).Public().(*rsa.PublicKey))
		if err != nil {
			return errors.Wrap(err, "Check signature failed")
		}
		return nil
	}
	return errors.New("unimplemented check")
}

// CheckSignature verifies that signature is a valid signature over signed from
// a crypto.PublicKey.
func checkSignature(c *x509.Certificate, signature []byte, publicKey *rsa.PublicKey) (err error) {
	hashType := crypto.SHA256
	if !hashType.Available() {
		return x509.ErrUnsupportedAlgorithm
	}

	h := hashType.New()
	h.Write(c.RawTBSCertificate)
	digest := h.Sum(nil)
	return errors.Wrap(rsa.VerifyPKCS1v15(publicKey, hashType, digest, signature), "Verify failed")
}
