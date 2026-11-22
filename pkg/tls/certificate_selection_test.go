package tls

import (
	"bytes"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/safe"
)

// newSelectionTestStore builds a store holding the given certificates, as the
// TLS manager does when it applies a configuration.
func newSelectionTestStore(t *testing.T, certs ...*CertAndStores) *CertificateStore {
	t.Helper()

	store := NewCertificateStore(nil)
	store.setDynamicCertificates(buildCertificateSet(t, certs...))

	return store
}

// buildCertificateSet parses the given certificates into a certificate set, as
// UpdateConfigs does.
func buildCertificateSet(t *testing.T, certs ...*CertAndStores) *certificateSet {
	t.Helper()

	builder := &certificateStoreBuilder{}

	for _, conf := range certs {
		cert, sans, err := parseCertificate(&conf.Certificate)
		require.NoError(t, err)

		builder.add(DefaultTLSStoreName, &CertificateData{Certificate: &cert}, sans)
	}

	return builder.set()
}

// TestSelectCertificate covers the certificate selection rules.
func TestSelectCertificate(t *testing.T) {
	rsaCert := newTestCertAndStores(t, testKeyRSA, nil, "app.example.test")
	ecdsaCert := newTestCertAndStores(t, testKeyECDSA, nil, "app.example.test")
	wildcardCert := newTestCertAndStores(t, testKeyRSA, nil, "*.example.test")
	otherCert := newTestCertAndStores(t, testKeyRSA, nil, "other.example.test")

	testCases := []struct {
		desc             string
		certs            []*CertAndStores
		serverName       string
		family           testKeyFamily
		expectedCert     *CertAndStores
		expectedMissing  bool
		expectedNoAccept bool
	}{
		{
			desc:         "both key families for the same name are kept",
			certs:        []*CertAndStores{rsaCert, ecdsaCert},
			serverName:   "app.example.test",
			family:       testKeyRSA,
			expectedCert: rsaCert,
		},
		{
			desc:         "ECDSA only client gets the ECDSA certificate",
			certs:        []*CertAndStores{rsaCert, ecdsaCert},
			serverName:   "app.example.test",
			family:       testKeyECDSA,
			expectedCert: ecdsaCert,
		},
		{
			desc:            "no certificate for the requested name",
			certs:           []*CertAndStores{rsaCert, ecdsaCert},
			serverName:      "unknown.example.test",
			family:          testKeyRSA,
			expectedMissing: true,
		},
		{
			desc:             "certificates exist, but none is acceptable",
			certs:            []*CertAndStores{rsaCert},
			serverName:       "app.example.test",
			family:           testKeyECDSA,
			expectedNoAccept: true,
		},
		{
			desc:         "exact certificate before a wildcard one",
			certs:        []*CertAndStores{wildcardCert, ecdsaCert, otherCert},
			serverName:   "app.example.test",
			family:       testKeyECDSA,
			expectedCert: ecdsaCert,
		},
		{
			desc:         "wildcard used when no exact certificate exists",
			certs:        []*CertAndStores{rsaCert, wildcardCert},
			serverName:   "other.example.test",
			family:       testKeyRSA,
			expectedCert: wildcardCert,
		},
		{
			desc:         "exact certificate of another name is not used",
			certs:        []*CertAndStores{rsaCert, wildcardCert, otherCert},
			serverName:   "other.example.test",
			family:       testKeyRSA,
			expectedCert: otherCert,
		},
		{
			desc:         "wildcard used for a name without any exact certificate",
			certs:        []*CertAndStores{rsaCert, wildcardCert},
			serverName:   "unknown.example.test",
			family:       testKeyRSA,
			expectedCert: wildcardCert,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			store := newSelectionTestStore(t, test.certs...)

			clientHello := newTestClientHelloForFamily(test.serverName, test.family)

			certificateData, reason := store.getBestCertificate(clientHello, true)

			if test.expectedMissing {
				assert.Nil(t, certificateData)
				assert.Equal(t, reasonNoCertificateForName, reason)
				return
			}

			if test.expectedNoAccept {
				assert.Nil(t, certificateData)
				assert.Equal(t, reasonNoAcceptableCertificate, reason)
				return
			}

			require.NotNil(t, certificateData)
			assert.Empty(t, reason)
			assert.Equal(t, parseTestLeaf(t, test.expectedCert).Raw, certificateData.Certificate.Leaf.Raw)
		})
	}
}

// TestSelectCertificate_FixedPriority ensures that, when a client supports both
// key families, the same certificate is always selected, whatever the
// configuration order.
func TestSelectCertificate_FixedPriority(t *testing.T) {
	rsaCert := newTestCertAndStores(t, testKeyRSA, nil, "app.example.test")
	ecdsaCert := newTestCertAndStores(t, testKeyECDSA, nil, "app.example.test")

	orders := [][]*CertAndStores{
		{rsaCert, ecdsaCert},
		{ecdsaCert, rsaCert},
	}

	var expected []byte
	for _, certs := range orders {
		store := newSelectionTestStore(t, certs...)

		for range 20 {
			certificateData, _ := store.getBestCertificate(newTestClientHello("app.example.test"), true)
			require.NotNil(t, certificateData)

			if expected == nil {
				expected = certificateData.Certificate.Leaf.Raw
			}

			assert.Equal(t, expected, certificateData.Certificate.Leaf.Raw)
		}
	}
}

// TestSelectCertificate_ReadOnly ensures the selection does not modify the store
// nor the certificates it holds.
func TestSelectCertificate_ReadOnly(t *testing.T) {
	store := newSelectionTestStore(t,
		newTestCertAndStores(t, testKeyRSA, nil, "app.example.test"),
		newTestCertAndStores(t, testKeyECDSA, nil, "app.example.test"),
	)

	entriesBefore := store.dynamicCertificates().entries
	generationBefore := store.dynamicCertificates().generation

	for _, family := range []testKeyFamily{testKeyRSA, testKeyECDSA} {
		store.getBestCertificate(newTestClientHelloForFamily("app.example.test", family), true)
	}

	assert.Equal(t, entriesBefore, store.dynamicCertificates().entries)
	assert.Equal(t, generationBefore, store.dynamicCertificates().generation)
}

// TestGetBestCertificate_CacheDoesNotCrossCapabilities ensures a selection made
// for a client is never returned to a client with different capabilities.
func TestGetBestCertificate_CacheDoesNotCrossCapabilities(t *testing.T) {
	rsaCert := newTestCertAndStores(t, testKeyRSA, nil, "app.example.test")
	ecdsaCert := newTestCertAndStores(t, testKeyECDSA, nil, "app.example.test")

	store := &CertificateStore{
		DynamicCerts: safe.New(buildCertificateSet(t, rsaCert, ecdsaCert)),
		CertCache:    cache.New(1*time.Hour, 10*time.Minute),
	}

	rsaLeaf := parseTestLeaf(t, rsaCert)
	ecdsaLeaf := parseTestLeaf(t, ecdsaCert)

	sequence := []struct {
		family testKeyFamily
		leaf   []byte
	}{
		{testKeyECDSA, ecdsaLeaf.Raw},
		{testKeyRSA, rsaLeaf.Raw},
		{testKeyRSA, rsaLeaf.Raw},
		{testKeyECDSA, ecdsaLeaf.Raw},
	}

	for range 10 {
		for _, step := range sequence {
			served := store.GetBestCertificate(newTestClientHelloForFamily("app.example.test", step.family))
			require.NotNil(t, served)
			assert.Equal(t, step.leaf, served.Leaf.Raw)
		}
	}
}

// TestGetBestCertificate_CacheInvalidatedOnUpdate ensures a certificate removed by
// a configuration update is not served from the cache anymore.
func TestGetBestCertificate_CacheInvalidatedOnUpdate(t *testing.T) {
	firstCert := newTestCertAndStores(t, testKeyRSA, nil, "app.example.test")
	store := newSelectionTestStore(t, firstCert)

	firstLeaf := parseTestLeaf(t, firstCert)
	served := store.GetBestCertificate(newTestClientHello("app.example.test"))
	require.NotNil(t, served)
	require.Equal(t, firstLeaf.Raw, served.Leaf.Raw)

	replacementCert := newTestCertAndStores(t, testKeyRSA, nil, "app.example.test")
	store.setDynamicCertificates(buildCertificateSet(t, replacementCert))

	replacementLeaf := parseTestLeaf(t, replacementCert)
	served = store.GetBestCertificate(newTestClientHello("app.example.test"))
	require.NotNil(t, served)
	assert.Equal(t, replacementLeaf.Raw, served.Leaf.Raw)

	store.setDynamicCertificates(buildCertificateSet(t))

	assert.Nil(t, store.GetBestCertificate(newTestClientHello("app.example.test")))
}

// TestBuildCertificateSet_Deduplication ensures only certificates with the exact
// same content are skipped.
func TestBuildCertificateSet_Deduplication(t *testing.T) {
	rsaCert := newTestCertAndStores(t, testKeyRSA, nil, "app.example.test")
	ecdsaCert := newTestCertAndStores(t, testKeyECDSA, nil, "app.example.test")

	set := buildCertificateSet(t, rsaCert, ecdsaCert, rsaCert)

	require.Len(t, set.entries, 2)
}

// TestBuildCertificateSet_PartialParseFailure ensures a certificate that cannot be
// parsed is skipped, without emptying the store.
func TestBuildCertificateSet_PartialParseFailure(t *testing.T) {
	builder := &certificateStoreBuilder{}

	validCert := newTestCertAndStores(t, testKeyRSA, nil, "app.example.test")
	cert, sans, err := parseCertificate(&validCert.Certificate)
	require.NoError(t, err)
	builder.add(DefaultTLSStoreName, &CertificateData{Certificate: &cert}, sans)

	invalidCert := &CertAndStores{Certificate: Certificate{CertFile: "not a certificate", KeyFile: "not a key"}} //nolint:modernize // The embedded field must be initialized explicitly.
	_, _, err = parseCertificate(&invalidCert.Certificate)
	require.Error(t, err)

	set := builder.set()

	require.Len(t, set.entries, 1)

	store := NewCertificateStore(nil)
	store.setDynamicCertificates(set)

	served := store.GetBestCertificate(newTestClientHello("app.example.test"))
	require.NotNil(t, served)
	assert.Equal(t, parseTestLeaf(t, validCert).Raw, served.Leaf.Raw)
}

// TestBuildCertificateSet_StoresAreIsolated ensures the challenge certificates and
// the regular traffic certificates live in separate stores.
func TestBuildCertificateSet_StoresAreIsolated(t *testing.T) {
	challengeCert := newTestCertAndStores(t, testKeyRSA, []string{"acme-tls/1"}, "app.example.test")
	trafficCert := newTestCertAndStores(t, testKeyECDSA, nil, "app.example.test")

	stores := map[string]*certificateStoreBuilder{}

	for _, conf := range []*CertAndStores{challengeCert, trafficCert} {
		cert, sans, err := parseCertificate(&conf.Certificate)
		require.NoError(t, err)

		for _, storeName := range conf.Stores {
			builder, ok := stores[storeName]
			if !ok {
				builder = &certificateStoreBuilder{}
				stores[storeName] = builder
			}

			builder.add(storeName, &CertificateData{Certificate: &cert}, sans)
		}
	}

	require.Contains(t, stores, "acme-tls/1")

	challengeStore := NewCertificateStore(nil)
	challengeStore.setDynamicCertificates(stores["acme-tls/1"].set())

	served := challengeStore.GetBestCertificate(newTestClientHello("app.example.test"))
	require.NotNil(t, served)
	assert.Equal(t, parseTestLeaf(t, challengeCert).Raw, served.Leaf.Raw)
}

// TestCertificateSelection_ConcurrentUpdate ensures a configuration update is
// applied as a whole while handshakes are selecting certificates: every
// selection observes either the previous snapshot or the new one, never a mix.
func TestCertificateSelection_ConcurrentUpdate(t *testing.T) {
	setA := buildCertificateSet(t,
		newTestCertAndStores(t, testKeyRSA, nil, "app.example.test"),
		newTestCertAndStores(t, testKeyECDSA, nil, "app.example.test"),
	)
	setB := buildCertificateSet(t,
		newTestCertAndStores(t, testKeyRSA, nil, "app.example.test"),
		newTestCertAndStores(t, testKeyECDSA, nil, "app.example.test"),
	)

	store := NewCertificateStore(nil)
	store.setDynamicCertificates(setA)

	// Every certificate the store can ever serve must belong to one of the two
	// snapshots: anything else would be a mix of both.
	knownLeaves := make([][]byte, 0, len(setA.entries)+len(setB.entries))
	for _, entry := range append(slices.Clone(setA.entries), setB.entries...) {
		knownLeaves = append(knownLeaves, entry.data.Certificate.Leaf.Raw)
	}

	var wg sync.WaitGroup

	for range 4 {
		wg.Go(func() {
			for range 2000 {
				for _, family := range []testKeyFamily{testKeyRSA, testKeyECDSA} {
					certificateData, _ := store.getBestCertificate(newTestClientHelloForFamily("app.example.test", family), true)
					if certificateData == nil {
						t.Error("selection returned no certificate")
						return
					}

					if !slices.ContainsFunc(knownLeaves, func(leaf []byte) bool {
						return bytes.Equal(leaf, certificateData.Certificate.Leaf.Raw)
					}) {
						t.Error("selection returned a certificate from outside the published snapshots")
						return
					}
				}
			}
		})
	}

	for range 50 {
		store.setDynamicCertificates(setB)
		store.setDynamicCertificates(setA)
	}

	wg.Wait()
}

// TestCertificateSelection_LogsReasonsAndNoSecrets ensures the selection logs
// carry a machine-readable reason, and neither the private key nor the
// certificate content.
func TestCertificateSelection_LogsReasonsAndNoSecrets(t *testing.T) {
	rsaCert := newTestCertAndStores(t, testKeyRSA, nil, "app.example.test")

	tests := []struct {
		desc             string
		serverName       string
		expectedReason   string
		expectedLogEntry string
	}{
		{
			desc:             "no acceptable certificate",
			serverName:       "app.example.test",
			expectedReason:   reasonNoAcceptableCertificate,
			expectedLogEntry: "and the default certificate is not either",
		},
		{
			desc:             "no certificate for the name",
			serverName:       "unknown.example.test",
			expectedReason:   reasonNoCertificateForName,
			expectedLogEntry: "Serving default certificate",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			var logs bytes.Buffer

			originalLogger := log.Logger
			log.Logger = zerolog.New(&logs).Level(zerolog.DebugLevel)
			t.Cleanup(func() { log.Logger = originalLogger })

			manager := newTestManager(t, rsaCert)
			config, err := manager.Get(DefaultTLSStoreName, DefaultTLSConfigName)
			require.NoError(t, err)

			clientHello := newTestClientHelloForFamily(test.serverName, testKeyECDSA)

			if test.expectedReason == reasonNoCertificateForName {
				// The default certificate is usable, so it is served.
				clientHello = newTestClientHelloForFamily(test.serverName, testKeyRSA)
			}

			_, _ = config.GetCertificate(clientHello)

			output := logs.String()
			assert.Contains(t, output, test.expectedReason)
			assert.Contains(t, output, test.expectedLogEntry)

			// The private key and the certificate content must never be logged.
			_, keyPEM, _ := newTestCertificate(t, testKeyRSA, "app.example.test")
			assert.NotContains(t, output, string(keyPEM))
			assert.NotContains(t, output, string(rsaCert.CertFile))
		})
	}
}
