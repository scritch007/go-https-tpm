package main

import (
	"crypto"
	"crypto/tls"
	"fmt"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/scritch007/go-https-tpm"
	https_tpm3 "github.com/scritch007/go-https-tpm/pkg/tpm2"
	https_tpm2 "github.com/scritch007/go-https-tpm/pkg/tpmk"
	"net/http"
	"os"

	"github.com/pkg/errors"
)

func main() {

	var pk crypto.Signer
	var err error
	if os.Getenv("old") != "" {
		fmt.Println("Using old library")
		pk, err = https_tpm3.LoadPrivateKeyFromTPM2("sim", tpmutil.Handle(0x81000000), "")
		if err != nil {
			panic(err)
		}
	} else {
		fmt.Println("Using new library")
		pk, err = https_tpm2.LoadPrivateKeyFromTPM("sim", tpmutil.Handle(0x81000000), "")
		if err != nil {
			panic(err)
		}
	}
	var cert []byte

	cert, err = https_tpm.LoadCertificateFromNVRam("sim", tpmutil.Handle(0x1500000), "")
	if err != nil {
		fmt.Println("Generating self signed certificate")
		cert, err = https_tpm.GenerateSelfSignCertificate(pk, "localhost")
		if err != nil {
			panic(err)
		}

		createCert := func() error {
			return https_tpm.WriteCertificateToNVRam("sim", cert, tpmutil.Handle(0x1500000), "")
		}

		if err := createCert(); err != nil {
			tpmErr, ok := err.(tpm2.Error)

			if !ok || tpmErr.Code != tpm2.RCNVDefined {
				panic(err)
			}
			if err = https_tpm.DeleteCertificateFromNVRam("sim", tpmutil.Handle(0x1500000), ""); err != nil {
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
