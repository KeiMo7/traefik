package tls

import (
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/safe"
)

func TestGetBestCertificate(t *testing.T) {
	// TODO Add tests for defaultCert
	testCases := []struct {
		desc          string
		domainToCheck string
		dynamicCert   string
		expectedCert  string
		uppercase     bool
	}{
		{
			desc:          "Empty Store, returns no certs",
			domainToCheck: "snitest.com",
			dynamicCert:   "",
			expectedCert:  "",
		},
		{
			desc:          "Best Match with no corresponding",
			domainToCheck: "snitest.com",
			dynamicCert:   "snitest.org",
			expectedCert:  "",
		},
		{
			desc:          "Best Match",
			domainToCheck: "snitest.com",
			dynamicCert:   "snitest.com",
			expectedCert:  "snitest.com",
		},
		{
			desc:          "Best Match with dynamic wildcard",
			domainToCheck: "www.snitest.com",
			dynamicCert:   "*.snitest.com",
			expectedCert:  "*.snitest.com",
		},
		{
			desc:          "Best Match with dynamic wildcard only, case-insensitive",
			domainToCheck: "bar.www.snitest.com",
			dynamicCert:   "*.www.snitest.com",
			expectedCert:  "*.www.snitest.com",
			uppercase:     true,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var dynamicCerts []*certificateEntry
			if test.dynamicCert != "" {
				cert, err := loadTestCert(test.dynamicCert, test.uppercase)
				require.NoError(t, err)
				dynamicCerts = []*certificateEntry{{
					data:       &CertificateData{Certificate: cert},
					domains:    []string{strings.ToLower(test.dynamicCert)},
					domainsKey: strings.ToLower(test.dynamicCert),
				}}
			}

			store := &CertificateStore{
				DynamicCerts: safe.New(&certificateSet{entries: dynamicCerts}),
				CertCache:    cache.New(1*time.Hour, 10*time.Minute),
			}

			var expected *tls.Certificate
			if test.expectedCert != "" {
				cert, err := loadTestCert(test.expectedCert, test.uppercase)
				require.NoError(t, err)
				expected = cert
			}

			clientHello := newTestClientHello(test.domainToCheck)

			actual := store.GetBestCertificate(clientHello)
			assert.Equal(t, expected, actual)
		})
	}
}

// newTestClientHello returns a ClientHelloInfo advertising the capabilities of a
// client that supports every certificate family Traefik can serve.
func newTestClientHello(serverName string) *tls.ClientHelloInfo {
	var cipherSuites []uint16
	for _, suite := range tls.CipherSuites() {
		cipherSuites = append(cipherSuites, suite.ID)
	}

	return &tls.ClientHelloInfo{
		ServerName: serverName,
		SupportedVersions: []uint16{
			tls.VersionTLS13,
			tls.VersionTLS12,
		},
		CipherSuites: cipherSuites,
		SignatureSchemes: []tls.SignatureScheme{
			tls.PSSWithSHA256,
			tls.PKCS1WithSHA256,
			tls.ECDSAWithP256AndSHA256,
			tls.Ed25519,
		},
		SupportedCurves: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
			tls.CurveP521,
		},
	}
}

// TestGetBestCertificate_SharedSAN ensures the selection stays deterministic
// when distinct certificates share a SAN matching the server name (https://github.com/traefik/traefik/issues/13286).
func TestGetBestCertificate_SharedSAN(t *testing.T) {
	wildcardCert := newTestCertificateData(t, testKeyRSA, "*.app.example.test", "app.example.test")
	exactCert := newTestCertificateData(t, testKeyRSA, "app.example.test")

	// Both certificates have a SAN matching app.example.test, but the exact-only
	// certificate must always win as its identifier sorts last.
	for range 100 {
		dynamicCerts := []*certificateEntry{
			{
				data:        wildcardCert,
				domains:     []string{"*.app.example.test", "app.example.test"},
				domainsKey:  "*.app.example.test,app.example.test",
				fingerprint: certificateFingerprint(wildcardCert.Certificate),
			},
			{
				data:        exactCert,
				domains:     []string{"app.example.test"},
				domainsKey:  "app.example.test",
				fingerprint: certificateFingerprint(exactCert.Certificate),
			},
		}

		store := &CertificateStore{
			DynamicCerts: safe.New(&certificateSet{entries: dynamicCerts}),
			CertCache:    cache.New(1*time.Hour, 10*time.Minute),
		}

		clientHello := newTestClientHello("app.example.test")
		assert.Same(t, exactCert.Certificate, store.GetBestCertificate(clientHello))
	}
}

func loadTestCert(certName string, uppercase bool) (*tls.Certificate, error) {
	replacement := "wildcard"
	if uppercase {
		replacement = "uppercase_wildcard"
	}

	staticCert, err := tls.LoadX509KeyPair(
		fmt.Sprintf("../../integration/fixtures/https/%s.cert", strings.ReplaceAll(certName, "*", replacement)),
		fmt.Sprintf("../../integration/fixtures/https/%s.key", strings.ReplaceAll(certName, "*", replacement)),
	)
	if err != nil {
		return nil, err
	}

	return &staticCert, nil
}
