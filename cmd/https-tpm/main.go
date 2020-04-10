package main

import (
	"crypto/tls"
	"github.com/folbricht/tpmk"
	"github.com/google/go-tpm/tpmutil"
	"github.com/scritch007/go-https-tpm"
	"net/http"

	"github.com/pkg/errors"
)

func main() {
	device := "sim"
	dev, err := tpmk.OpenDevice(device)
	if err != nil {
		panic(errors.Wrap(err, "opening "+device))
	}
	defer dev.Close()

	tlsConfig, err := https_tpm.NewTransport(dev, tpmutil.Handle(0x81000000), "localhost")
	if err != nil{
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
