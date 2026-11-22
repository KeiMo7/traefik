package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/types"
)

// testKeyFamily identifies the key family of a test certificate.
type testKeyFamily string

const (
	testKeyRSA   testKeyFamily = "rsa"
	testKeyECDSA testKeyFamily = "ecdsa"
)

// newTestCertificate returns a self-signed certificate for the given names,
// along with its PEM encoding, and stores the parsed leaf in the certificate.
func newTestCertificate(t *testing.T, family testKeyFamily, dnsNames ...string) (*tls.Certificate, []byte, []byte) {
	t.Helper()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	var (
		publicKey any
		signer    any
		keyPEM    []byte
	)

	switch family {
	case testKeyRSA:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		publicKey, signer = &key.PublicKey, key
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	case testKeyECDSA:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		publicKey = &key.PublicKey

		derKey, err := x509.MarshalECPrivateKey(key)
		require.NoError(t, err)
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: derKey})
		signer = key
	default:
		t.Fatalf("unknown key family %q", family)
	}

	derCert, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, signer)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(derCert)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derCert})

	return &tls.Certificate{
		Certificate: [][]byte{derCert},
		PrivateKey:  signer,
		Leaf:        leaf,
	}, certPEM, keyPEM
}

// newTestCertificateData returns a CertificateData for the given certificate of a
// store, as built by the TLS manager.
func newTestCertificateData(t *testing.T, family testKeyFamily, dnsNames ...string) *CertificateData {
	t.Helper()

	cert, _, _ := newTestCertificate(t, family, dnsNames...)

	return &CertificateData{Certificate: cert}
}

// newTestCertAndStores returns a CertAndStores configuration entry for the given
// certificate.
func newTestCertAndStores(t *testing.T, family testKeyFamily, stores []string, dnsNames ...string) *CertAndStores {
	t.Helper()

	_, certPEM, keyPEM := newTestCertificate(t, family, dnsNames...)

	return &CertAndStores{
		Certificate: Certificate{CertFile: types.FileOrContent(certPEM), KeyFile: types.FileOrContent(keyPEM)}, //nolint:modernize // The embedded field must be initialized explicitly.
		Stores:      stores,
	}
}

// newTestClientHelloForFamily returns a ClientHelloInfo advertising the
// capabilities of a client that only supports the given key family.
func newTestClientHelloForFamily(serverName string, family testKeyFamily) *tls.ClientHelloInfo {
	hello := newTestClientHello(serverName)

	switch family {
	case testKeyRSA:
		hello.SignatureSchemes = []tls.SignatureScheme{
			tls.PSSWithSHA256,
			tls.PKCS1WithSHA256,
			tls.PSSWithSHA384,
			tls.PKCS1WithSHA384,
		}
		hello.SupportedCurves = []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		}
	case testKeyECDSA:
		hello.SignatureSchemes = []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.ECDSAWithP384AndSHA384,
		}
	default:
		panic("unknown key family " + string(family))
	}

	return hello
}
