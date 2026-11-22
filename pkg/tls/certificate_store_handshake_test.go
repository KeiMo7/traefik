package tls

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testServerName = "multi.example.test"

// startTestTLSServer starts a TLS server using the given configuration, and
// returns its address.
// The certificates are served by the GetCertificate callback of the
// configuration, as in a Traefik entryPoint.
func startTestTLSServer(t *testing.T, config *tls.Config) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			go func() {
				defer conn.Close()
				// The handshake error is irrelevant here: the client asserts what it receives.
				_ = tls.Server(conn, config).Handshake()
			}()
		}
	}()

	return listener.Addr().String()
}

// dialTestServer performs a real TLS handshake against the given address, and
// returns the certificate served by the server.
func dialTestServer(t *testing.T, addr string, config *tls.Config) (*x509.Certificate, error) {
	t.Helper()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, config)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates[0], nil
}

// rsaOnlyClientConfig returns the configuration of a client that can only
// validate RSA certificates, by only offering TLS 1.2 cipher suites relying on
// RSA signatures.
func rsaOnlyClientConfig(serverName string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
}

// ecdsaOnlyClientConfig returns the configuration of a client that can only
// validate ECDSA certificates, by only offering TLS 1.2 cipher suites relying on
// ECDSA signatures.
func ecdsaOnlyClientConfig(serverName string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}
}

// anyFamilyClientConfig returns the configuration of a client supporting both
// RSA and ECDSA certificates.
func anyFamilyClientConfig(serverName string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
	}
}

func newTestManager(t *testing.T, certificates ...*CertAndStores) *Manager {
	t.Helper()

	manager := NewManager(nil)
	manager.UpdateConfigs(t.Context(), nil, map[string]Options{
		DefaultTLSConfigName: DefaultTLSOptions,
	}, certificates)

	return manager
}

func startTestManagerServer(t *testing.T, manager *Manager) string {
	t.Helper()

	config, err := manager.Get(DefaultTLSStoreName, DefaultTLSConfigName)
	require.NoError(t, err)

	return startTestTLSServer(t, config)
}

// TestHandshake_MultipleKeyFamiliesSameName ensures that two certificates for
// the same host name, with different key families, are both kept and selected
// according to what the client supports.
func TestHandshake_MultipleKeyFamiliesSameName(t *testing.T) {
	rsaCert := newTestCertAndStores(t, testKeyRSA, nil, testServerName)
	ecdsaCert := newTestCertAndStores(t, testKeyECDSA, nil, testServerName)

	manager := newTestManager(t, rsaCert, ecdsaCert)
	addr := startTestManagerServer(t, manager)

	rsaLeaf := parseTestLeaf(t, rsaCert)
	ecdsaLeaf := parseTestLeaf(t, ecdsaCert)

	t.Run("RSA only client gets the RSA certificate", func(t *testing.T) {
		served, err := dialTestServer(t, addr, rsaOnlyClientConfig(testServerName))
		require.NoError(t, err)
		assert.Equal(t, rsaLeaf.Raw, served.Raw)
	})

	t.Run("ECDSA only client gets the ECDSA certificate", func(t *testing.T) {
		served, err := dialTestServer(t, addr, ecdsaOnlyClientConfig(testServerName))
		require.NoError(t, err)
		assert.Equal(t, ecdsaLeaf.Raw, served.Raw)
	})

	t.Run("interleaved clients with different capabilities", func(t *testing.T) {
		// The selection of a client must never be reused for another client,
		// whatever the connection order.
		sequence := []struct {
			config *tls.Config
			leaf   *x509.Certificate
		}{
			{rsaOnlyClientConfig(testServerName), rsaLeaf},
			{ecdsaOnlyClientConfig(testServerName), ecdsaLeaf},
			{ecdsaOnlyClientConfig(testServerName), ecdsaLeaf},
			{rsaOnlyClientConfig(testServerName), rsaLeaf},
		}

		for i := range 5 {
			for _, step := range sequence {
				served, err := dialTestServer(t, addr, step.config)
				require.NoError(t, err, "round %d", i)
				assert.Equal(t, step.leaf.Raw, served.Raw, "round %d", i)
			}
		}
	})

	t.Run("client supporting both families gets a stable certificate", func(t *testing.T) {
		first, err := dialTestServer(t, addr, anyFamilyClientConfig(testServerName))
		require.NoError(t, err)

		for range 10 {
			served, err := dialTestServer(t, addr, anyFamilyClientConfig(testServerName))
			require.NoError(t, err)
			assert.Equal(t, first.Raw, served.Raw)
		}
	})
}

// TestHandshake_ExactOverWildcard ensures an exact certificate is used before a
// wildcard one, and that the two certificates of a same host are both kept when
// they match through different names.
func TestHandshake_ExactOverWildcard(t *testing.T) {
	wildcardCert := newTestCertAndStores(t, testKeyRSA, nil, "*.example.test")
	exactCert := newTestCertAndStores(t, testKeyECDSA, nil, testServerName)

	manager := newTestManager(t, wildcardCert, exactCert)
	addr := startTestManagerServer(t, manager)

	exactLeaf := parseTestLeaf(t, exactCert)

	served, err := dialTestServer(t, addr, anyFamilyClientConfig(testServerName))
	require.NoError(t, err)
	assert.Equal(t, exactLeaf.Raw, served.Raw)

	wildcardLeaf := parseTestLeaf(t, wildcardCert)

	served, err = dialTestServer(t, addr, anyFamilyClientConfig("other.example.test"))
	require.NoError(t, err)
	assert.Equal(t, wildcardLeaf.Raw, served.Raw)
}

// TestHandshake_NoServerName ensures the local address fallback still selects a
// usable certificate when several certificates are configured.
func TestHandshake_NoServerName(t *testing.T) {
	rsaCert := newTestCertAndStores(t, testKeyRSA, nil, testServerName)
	ecdsaCert := newTestCertAndStores(t, testKeyECDSA, nil, testServerName)
	ipCert := newTestCertAndStores(t, testKeyRSA, nil, "127.0.0.1")

	manager := newTestManager(t, rsaCert, ecdsaCert, ipCert)
	addr := startTestManagerServer(t, manager)

	ipLeaf := parseTestLeaf(t, ipCert)

	// No ServerName: no SNI is sent, and the local address of the connection is used.
	config := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}

	served, err := dialTestServer(t, addr, config)
	require.NoError(t, err)
	assert.Equal(t, ipLeaf.Raw, served.Raw)
}

// TestHandshake_NoAcceptableCertificate ensures the handshake fails right away,
// with a diagnostic alert, when the client and the server have no certificate in
// common.
func TestHandshake_NoAcceptableCertificate(t *testing.T) {
	// Only an RSA certificate is configured, and the default certificate is RSA
	// as well, so an ECDSA-only client cannot be served at all.
	manager := newTestManager(t, newTestCertAndStores(t, testKeyRSA, nil, testServerName))
	addr := startTestManagerServer(t, manager)

	start := time.Now()
	_, err := dialTestServer(t, addr, ecdsaOnlyClientConfig(testServerName))
	require.Error(t, err)

	// The connection is closed during the handshake, it does not wait for a timeout.
	assert.Less(t, time.Since(start), 3*time.Second)

	// The server reports an "unrecognized name" alert, as for any other missing
	// certificate, rather than failing later in the handshake.
	assert.Contains(t, err.Error(), "tls: unrecognized name")
}

// TestHandshake_StrictSNINoAcceptableCertificate ensures the strict SNI mode still
// refuses the connection when no certificate is acceptable.
func TestHandshake_StrictSNINoAcceptableCertificate(t *testing.T) {
	manager := NewManager(nil)
	manager.UpdateConfigs(t.Context(), nil, map[string]Options{
		"strict": {SniStrict: true},
	}, []*CertAndStores{newTestCertAndStores(t, testKeyRSA, nil, testServerName)})

	config, err := manager.Get(DefaultTLSStoreName, "strict")
	require.NoError(t, err)

	addr := startTestTLSServer(t, config)

	_, err = dialTestServer(t, addr, ecdsaOnlyClientConfig(testServerName))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tls: unrecognized name")
}

// TestHandshake_ConfigUpdate ensures the next handshake uses the certificates of
// the latest configuration, and never a leftover of the previous one.
func TestHandshake_ConfigUpdate(t *testing.T) {
	firstCert := newTestCertAndStores(t, testKeyRSA, nil, testServerName)
	manager := newTestManager(t, firstCert)

	config, err := manager.Get(DefaultTLSStoreName, DefaultTLSConfigName)
	require.NoError(t, err)

	addr := startTestTLSServer(t, config)

	firstLeaf := parseTestLeaf(t, firstCert)

	served, err := dialTestServer(t, addr, anyFamilyClientConfig(testServerName))
	require.NoError(t, err)
	require.Equal(t, firstLeaf.Raw, served.Raw)

	// Replace the certificate for the same host name.
	replacementCert := newTestCertAndStores(t, testKeyRSA, nil, testServerName)
	manager.UpdateConfigs(t.Context(), nil, map[string]Options{DefaultTLSConfigName: DefaultTLSOptions}, []*CertAndStores{replacementCert})

	replacementLeaf := parseTestLeaf(t, replacementCert)

	served, err = dialTestServer(t, addr, anyFamilyClientConfig(testServerName))
	require.NoError(t, err)
	assert.Equal(t, replacementLeaf.Raw, served.Raw)

	// Remove every certificate: the default certificate is served, not the previous one.
	manager.UpdateConfigs(t.Context(), nil, map[string]Options{DefaultTLSConfigName: DefaultTLSOptions}, nil)

	served, err = dialTestServer(t, addr, anyFamilyClientConfig(testServerName))
	require.NoError(t, err)
	assert.NotEqual(t, replacementLeaf.Raw, served.Raw)
	assert.Equal(t, "TRAEFIK DEFAULT CERT", served.Subject.CommonName)
}

// TestHandshake_ACMECertificateIsolation ensures a challenge certificate cannot
// be selected for regular traffic.
func TestHandshake_ACMECertificateIsolation(t *testing.T) {
	challengeCert := newTestCertAndStores(t, testKeyRSA, []string{"acme-tls/1"}, testServerName)
	trafficCert := newTestCertAndStores(t, testKeyECDSA, nil, testServerName)

	manager := newTestManager(t, challengeCert, trafficCert)
	addr := startTestManagerServer(t, manager)

	trafficLeaf := parseTestLeaf(t, trafficCert)
	challengeLeaf := parseTestLeaf(t, challengeCert)

	served, err := dialTestServer(t, addr, anyFamilyClientConfig(testServerName))
	require.NoError(t, err)
	assert.Equal(t, trafficLeaf.Raw, served.Raw)

	challengeConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         testServerName,
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"acme-tls/1"},
	}

	served, err = dialTestServer(t, addr, challengeConfig)
	require.NoError(t, err)
	assert.Equal(t, challengeLeaf.Raw, served.Raw)
}

// parseTestLeaf parses the certificate of a test configuration entry.
func parseTestLeaf(t *testing.T, certAndStores *CertAndStores) *x509.Certificate {
	t.Helper()

	cert, err := tls.X509KeyPair([]byte(certAndStores.CertFile), []byte(certAndStores.KeyFile))
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)

	return leaf
}
