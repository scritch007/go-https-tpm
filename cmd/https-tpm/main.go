package main

import (
	"crypto/tls"
	"fmt"
	"github.com/google/go-tpm/tpmutil"
	"github.com/scritch007/go-https-tpm"
	"net/http"

	"github.com/pkg/errors"
)

func main() {

	pk, err := https_tpm.LoadPrivateKeyFromTPM("sim", tpmutil.Handle(0x81000000), "")
	if err != nil {
		panic(err)
	}
	var cert []byte

	cert, err = https_tpm.LoadCertificateFromNVRam("sim", tpmutil.Handle(0x1500000), "")
	if err != nil {
		fmt.Printf("Generating self signed certificate")
		cert, err = https_tpm.GenerateSelfSignCertificate(pk, "localhost")
		if err != nil {
			panic(err)
		}
		if err := https_tpm.WriteCertificateToNVRam("sim", cert, tpmutil.Handle(0x1500000), ""); err != nil {
			panic(err)
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
