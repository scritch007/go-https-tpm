package https_tpm

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"math/big"
	"strings"

	"github.com/chrisccoulson/go-tpm2"
	"github.com/pkg/errors"

	"io"
	"sync"
)

type Loader struct{}

// LoadPrivateKeyFromTPM return a private from TPM
func (Loader) LoadPrivateKeyFromTPM(device string, handle uint32, password string) (crypto.Signer, error) {

	w := &wrapperTPM2{
		device:   device,
		password: password,
	}
	return w, errors.Wrap(w.init(handle), "couldn't initialise key")
}

type wrapperTPM2 struct {
	device    string
	handle    tpm2.ResourceContext
	publicKey crypto.PublicKey
	lock      sync.Mutex
	password  string
	other     crypto.Signer
}

func (w *wrapperTPM2) Public() crypto.PublicKey {
	return w.publicKey
}

// Map a crypto.Hash algorithm to a tpm2 constant
var tpmToHashFunc = map[crypto.Hash]tpm2.HashAlgorithmId{
	crypto.SHA1:   tpm2.HashAlgorithmSHA1,
	crypto.SHA384: tpm2.HashAlgorithmSHA384,
	crypto.SHA256: tpm2.HashAlgorithmSHA256,
	crypto.SHA512: tpm2.HashAlgorithmSHA512,
}

// Map the crypto.Hash values to strings. Used to report errors
// when a Hash algorithm isn't available.
var hashToName = map[crypto.Hash]string{
	crypto.MD4:         "MD4",
	crypto.MD5:         "MD5",
	crypto.SHA1:        "SHA1",
	crypto.SHA224:      "SHA224",
	crypto.SHA256:      "SHA256",
	crypto.SHA384:      "SHA384",
	crypto.SHA512:      "SHA512",
	crypto.MD5SHA1:     "MD5SHA1",
	crypto.RIPEMD160:   "RIPEMD160",
	crypto.SHA3_224:    "SHA3_224",
	crypto.SHA3_256:    "SHA3_256",
	crypto.SHA3_384:    "SHA3_384",
	crypto.SHA3_512:    "SHA3_512",
	crypto.SHA512_224:  "SHA512_224",
	crypto.SHA512_256:  "SHA512_256",
	crypto.BLAKE2s_256: "BLAKE2s_256",
	crypto.BLAKE2b_256: "BLAKE2b_256",
	crypto.BLAKE2b_384: "BLAKE2b_384",
	crypto.BLAKE2b_512: "BLAKE2b_512",
}

func (w *wrapperTPM2) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	fmt.Println("Sign called")
	dev, err := w.openTPM()
	defer func() {
		w.closeTPM(dev)
	}()
	if err != nil {
		return nil, errors.Wrap(err, "Sign: retrieving private key")
	}

	hash, ok := tpmToHashFunc[opts.HashFunc()]
	if !ok {
		return nil, fmt.Errorf("unsupported hash algorithm: %d (%s)", opts.HashFunc(), hashToName[opts.HashFunc()])
	}

	inScheme := tpm2.SigScheme{
		Scheme:  tpm2.SigSchemeAlgRSASSA,
		Details: tpm2.SigSchemeU{Data: &tpm2.SigSchemeRSASSA{HashAlg: hash}}}

	if _, ok := opts.(*rsa.PSSOptions); ok {
		inScheme = tpm2.SigScheme{
			Scheme:  tpm2.SigSchemeAlgRSAPSS,
			Details: tpm2.SigSchemeU{Data: &tpm2.SigSchemeRSAPSS{HashAlg: hash}}}
	}
	//shaDigest := sha256.Sum256(digest)
	shaDigest := digest

	s, err := dev.Sign(w.handle, tpm2.Digest(shaDigest[:]), &inScheme, nil, nil)

	if err != nil {
		return nil, errors.Wrap(err, "sign failed")
	}

	if inScheme.Scheme == tpm2.SigSchemeAlgRSASSA {
		sig := (*tpm2.SignatureRSA)(s.Signature.RSASSA())
		if !sig.Hash.Supported() {
			return nil, errors.Wrap(err, "hash not supported")
		}
		signature = sig.Sig
	} else {
		sig := (*tpm2.SignatureRSA)(s.Signature.RSAPSS())
		if !sig.Hash.Supported() {
			return nil, errors.Wrap(err, "hash not supported")
		}
		signature = sig.Sig
	}
	return
}

func (w *wrapperTPM2) init(handle uint32) error {
	dev, err := w.openTPM()
	if dev != nil {
		defer w.closeTPM(dev)
	}
	if err != nil {
		return err
	}

	pkey, err := dev.CreateResourceContextFromTPM(tpm2.Handle(handle))
	if err != nil {
		return errors.Wrap(err, "couldn't get resource")
	}
	pub, _, _, err := dev.ReadPublic(pkey)
	if err != nil {
		return errors.Wrap(err, "couldn't get public key")
	}

	exp := int(pub.Params.RSADetail().Exponent)
	if exp == 0 {
		exp = tpm2.DefaultRSAExponent
	}
	pubKey := &rsa.PublicKey{N: new(big.Int).SetBytes(pub.Unique.RSA()), E: exp}

	w.publicKey = pubKey
	w.handle = pkey

	return nil
}

func (w *wrapperTPM2) openTPM() (*tpm2.TPMContext, error) {
	w.lock.Lock()
	return openTPM(w.device)
}

func openTPM(d string) (*tpm2.TPMContext, error) {
	var iow io.ReadWriteCloser
	var err error
	if d == "sim" {
		iow, err = tpm2.OpenMssim("", 2321, 2322)
	} else {
		iow, err = tpm2.OpenTPMDevice(d)
	}

	if err != nil {
		return nil, errors.Wrap(err, "couldn't open tpm connection")
	}
	dev, err := tpm2.NewTPMContext(iow)
	if err != nil {
		return nil, errors.Wrapf(err, "opening %s", d)
	}

	if err = dev.Startup(tpm2.StartupClear); err != nil {
		if !strings.Contains(err.Error(), "TPM_RC_INITIALIZE") {
			return nil, errors.Wrap(err, "startup error")
		}
	}
	return dev, nil
}

func (w *wrapperTPM2) closeTPM(dev *tpm2.TPMContext) {
	dev.Close()
	w.lock.Unlock()
}
