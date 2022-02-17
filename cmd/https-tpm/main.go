package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/go-tpm/tpm2"

	https_tpm "github.com/scritch007/go-https-tpm"
	https_tpm2 "github.com/scritch007/go-https-tpm/pkg/tpmk"

	"github.com/pkg/errors"
)

type loader interface {
	https_tpm.CertificateLoader
	https_tpm.PrivateKeyLoader
}

var (
	privateKey = flag.String("priv", "", "use private key")
	cert       = flag.String("cert", "", "will only be used if priv is provided")
)

func main() {

	flag.Parse()

	var pk crypto.Signer
	var err error
	var l loader

	fmt.Println("Using old library")
	l = https_tpm2.Loader{}

	device := "sim"
	privateKeyHandle := uint32(0x81000000)
	certificateHandle := uint32(0x1500000)

	if privateKey != nil && len(*privateKey) > 0 {
		b, err := ioutil.ReadFile(*privateKey)
		if err != nil {
			panic(err)
		}
		privPem, _ := pem.Decode(b)

		var parsedKey interface{}
		if parsedKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes); err != nil {
			if parsedKey, err = x509.ParsePKCS8PrivateKey(privPem.Bytes); err != nil { // note this returns type `interface{}`
				panic(err)
			}
		}
		privateKey, ok := parsedKey.(*rsa.PrivateKey)
		if !ok {
			panic("Invalid private key type")
		}
		if err = l.StorePrivateKey(device, privateKeyHandle, "", privateKey); err != nil {
			panic(err)
		}

		if cert != nil && len(*cert) > 0 {
			b, err = ioutil.ReadFile(*cert)
			if err != nil {
				panic(err)
			}

			if err = l.WriteCertificateToNVRam(device, b, certificateHandle, ""); err != nil {
				panic(err)
			}

		}
	}

	pk, err = l.LoadPrivateKeyFromTPM(device, privateKeyHandle, "")
	if err != nil {
		pk, err = l.GeneratePrivateKey(device, privateKeyHandle, "")
		if err != nil {
			panic(err)
		}
	}

	var cert []byte
	cert, err = l.LoadCertificateFromNVRam(device, certificateHandle, "")
	if err != nil {
		fmt.Printf("Generating self signed certificate, %v \n", err)
		cert, err = https_tpm.GenerateSelfSignCertificate(pk, "localhost")
		if err != nil {
			panic(err)
		}

		createCert := func() error {
			return l.WriteCertificateToNVRam(device, cert, certificateHandle, "")
		}

		if err = createCert(); err != nil {

			if tpmErr, ok := err.(tpm2.Error); !ok {
				panic(err)
			} else if tpmErr.Code != tpm2.RCNVDefined {
				panic(err)
			}
			if err = l.DeleteCertificateFromNVRam(device, certificateHandle, ""); err != nil {
				panic(err)
			}
			if err = createCert(); err != nil {
				panic(err)
			}
		}
	}

	tlsConfig, err := https_tpm.NewTransport(pk, cert)
	if err != nil {
		panic(errors.Wrap(err, "couldn't get transport"))
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("hello world"))
		}),
	}
	server.TLSConfig = tlsConfig

	ln, err := tls.Listen("tcp", ":10000", tlsConfig)
	if err != nil {
		panic(err)
	}

	err = server.Serve(ln)
	if err != nil {
		panic(err)
	}

}
