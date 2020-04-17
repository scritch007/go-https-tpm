package main

import (
	"crypto"
	"crypto/tls"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"github.com/scritch007/go-https-tpm"
	https_tpm3 "github.com/scritch007/go-https-tpm/pkg/tpm2"
	https_tpm2 "github.com/scritch007/go-https-tpm/pkg/tpmk"
	"net/http"
	"os"

	"github.com/pkg/errors"
)

type loader interface {
	https_tpm.CertificateLoader
	https_tpm.PrivateKeyLoader
}

func main() {

	var pk crypto.Signer
	var err error
	var l loader
	if os.Getenv("old") != "" {
		fmt.Println("Using old library")
		l = https_tpm2.Loader{}
	} else {
		fmt.Println("Using new library")
		l = https_tpm3.Loader{}
	}
	pk, err = l.LoadPrivateKeyFromTPM("sim", 0x81000000, "")
	if err != nil {
		panic(err)
	}
	var cert []byte

	cert, err = l.LoadCertificateFromNVRam("sim", 0x1500000, "")
	if err != nil {
		fmt.Printf("Generating self signed certificate, %v \n", err)
		cert, err = https_tpm.GenerateSelfSignCertificate(pk, "localhost")
		if err != nil {
			panic(err)
		}

		createCert := func() error {
			return l.WriteCertificateToNVRam("sim", cert, 0x1500000, "")
		}

		if err := createCert(); err != nil {
			tpmErr, ok := err.(tpm2.Error)

			if !ok || tpmErr.Code != tpm2.RCNVDefined {
				panic(err)
			}
			if err = l.DeleteCertificateFromNVRam("sim", 0x1500000, ""); err != nil {
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
