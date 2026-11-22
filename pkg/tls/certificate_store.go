package tls

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/safe"
)

// Reasons why certificate selection did not return a certificate.
// They are attached to the selection logs, so that a missing certificate can be
// told apart from a certificate the client cannot use.
const (
	reasonNoCertificateForName    = "no_certificate_for_name"
	reasonNoAcceptableCertificate = "no_acceptable_certificate"
)

// CertificateData holds runtime data for runtime TLS certificate handling.
type CertificateData struct {
	Hash        string
	Certificate *tls.Certificate
}

// certificateEntry is a certificate of a store, along with the certificate
// names it was configured for.
type certificateEntry struct {
	data    *CertificateData
	domains []string
	// domainsKey is the sorted certificate names joined with commas, as used by
	// GetAllDomains and GetCertificate.
	domainsKey string
	// fingerprint identifies the certificate content. Certificates sharing the
	// same names are ordered by it, so that the selection does not depend on the
	// order in which they happen to be configured.
	fingerprint string
}

// certificateSet is an immutable snapshot of the certificates of a store.
// A configuration update publishes a new snapshot at once, so that certificate
// selection never observes a partially updated store.
type certificateSet struct {
	entries []*certificateEntry
	// generation changes on every update of the owning store, and is part of the
	// selection cache keys, so that entries cached for a previous snapshot are
	// never used for a newer one.
	generation uint64
}

// certificateCandidate is a certificate matching a requested server name.
type certificateCandidate struct {
	entry *certificateEntry
	// exact is true when a configured certificate name matches the server name
	// verbatim, and false when the match is a wildcard match.
	exact bool
}

// CertificateStore store for dynamic certificates.
type CertificateStore struct {
	DynamicCerts       *safe.Safe
	DefaultCertificate *CertificateData
	CertCache          *cache.Cache

	ocspStapler *ocspStapler

	generationMu sync.Mutex
	generation   uint64
}

// NewCertificateStore create a store for dynamic certificates.
func NewCertificateStore(ocspStapler *ocspStapler) *CertificateStore {
	return &CertificateStore{
		DynamicCerts: safe.New(&certificateSet{}),
		CertCache:    cache.New(1*time.Hour, 10*time.Minute),
		ocspStapler:  ocspStapler,
	}
}

// GetAllDomains return a slice with all the certificate domain.
func (c *CertificateStore) GetAllDomains() []string {
	allDomains := c.getDefaultCertificateDomains()

	for _, entry := range c.dynamicCertificates().entries {
		allDomains = append(allDomains, entry.domainsKey)
	}

	return allDomains
}

// GetDefaultCertificate returns the default certificate.
func (c *CertificateStore) GetDefaultCertificate() *tls.Certificate {
	if c == nil {
		return nil
	}

	c.applyStaple(c.DefaultCertificate)

	return c.DefaultCertificate.Certificate
}

// GetBestCertificate returns the best match certificate for the client, and
// caches the certificates matching the requested server name.
func (c *CertificateStore) GetBestCertificate(clientHello *tls.ClientHelloInfo) *tls.Certificate {
	certificateData, _ := c.getBestCertificate(clientHello, true)
	if certificateData == nil {
		return nil
	}

	return certificateData.Certificate
}

// candidates returns the certificates matching the server name, by decreasing
// priority. The order only depends on the certificates themselves, never on the
// order in which they were iterated, and certificates that cannot be told apart
// keep their configuration order, so that repeated selections with the same
// inputs return the same certificate.
func (s *certificateSet) candidates(serverName string) []certificateCandidate {
	var candidates []certificateCandidate

	for _, entry := range s.entries {
		exact, ok := matchDomain(serverName, entry.domains)
		if !ok {
			continue
		}

		candidates = append(candidates, certificateCandidate{entry: entry, exact: exact})
	}

	slices.SortStableFunc(candidates, func(a, b certificateCandidate) int {
		// An exact match is preferred over a wildcard match.
		if a.exact != b.exact {
			if a.exact {
				return -1
			}
			return 1
		}

		// Preserve the historical ordering: the certificate whose name set sorts
		// last lexicographically comes first.
		if diff := strings.Compare(b.entry.domainsKey, a.entry.domainsKey); diff != 0 {
			return diff
		}

		// Certificates sharing the same name set (e.g. one RSA and one ECDSA
		// certificate for the same host name) are ordered by content, which keeps
		// the priority of a given certificate independent from the order in which
		// the certificates happen to be configured.
		return strings.Compare(a.entry.fingerprint, b.entry.fingerprint)
	})

	return candidates
}

// certificateUsableByClient returns whether the client can use the certificate,
// given the capabilities it advertised in its ClientHello.
// The certificate names are deliberately not checked: they are matched against the
// configured certificate names beforehand, and the default certificate has always
// been served even when it does not carry the requested name.
func certificateUsableByClient(clientHello *tls.ClientHelloInfo, certificate *tls.Certificate) bool {
	if certificate == nil {
		return false
	}

	// A ClientHello without any protocol version has not been built from an actual
	// handshake: there is no capability to filter on, so the certificate is kept.
	if len(clientHello.SupportedVersions) == 0 {
		return true
	}

	// SupportsCertificate also verifies the certificate against the server name of
	// the ClientHello, which is cleared to only take the capabilities into account.
	capabilitiesOnly := *clientHello
	capabilitiesOnly.ServerName = ""

	return capabilitiesOnly.SupportsCertificate(certificate) == nil
}

// GetCertificate returns the first certificate matching all the given domains.
func (c *CertificateStore) GetCertificate(domains []string) *CertificateData {
	if c == nil {
		return nil
	}

	sortedDomains := slices.Clone(domains)
	slices.Sort(sortedDomains)
	domainsKey := strings.Join(sortedDomains, ",")

	set := c.dynamicCertificates()

	cacheKey := "domains\x00" + domainsKey + "\x00" + strconv.FormatUint(set.generation, 10)

	if c.CertCache != nil {
		if item, ok := c.CertCache.Get(cacheKey); ok {
			if certificateData, ok := item.(*CertificateData); ok {
				return certificateData
			}
		}
	}

	for _, entry := range set.entries {
		if domainsKey == entry.domainsKey {
			if c.CertCache != nil {
				c.CertCache.SetDefault(cacheKey, entry.data)
			}
			return entry.data
		}

		var matchedDomains []string
		for _, certDomain := range entry.domains {
			for _, checkDomain := range sortedDomains {
				if certDomain == checkDomain {
					matchedDomains = append(matchedDomains, certDomain)
				}
			}
		}

		if len(matchedDomains) == len(sortedDomains) {
			if c.CertCache != nil {
				c.CertCache.SetDefault(cacheKey, entry.data)
			}
			return entry.data
		}
	}

	return nil
}

// ResetCache clears the cache in the store.
func (c *CertificateStore) ResetCache() {
	if c.CertCache != nil {
		c.CertCache.Flush()
	}
}

// setDynamicCertificates publishes a new certificate snapshot for the store as a
// whole, and drops the selections cached for the previous snapshot.
func (c *CertificateStore) setDynamicCertificates(set *certificateSet) {
	if set == nil {
		set = &certificateSet{}
	}

	c.generationMu.Lock()
	c.generation++

	// The published snapshot is never mutated afterwards: the caller may reuse the
	// snapshot it handed over, and handshakes may be reading it at the same time.
	published := &certificateSet{
		entries:    set.entries,
		generation: c.generation,
	}
	c.DynamicCerts.Set(published)

	if c.CertCache != nil {
		c.CertCache.Flush()
	}
	c.generationMu.Unlock()
}

// dynamicCertificates returns the current certificate set, which must be
// considered read-only.
func (c *CertificateStore) dynamicCertificates() *certificateSet {
	if c == nil || c.DynamicCerts == nil {
		return &certificateSet{}
	}

	set, ok := c.DynamicCerts.Get().(*certificateSet)
	if !ok || set == nil {
		return &certificateSet{}
	}

	return set
}

// getBestCertificate returns the best match certificate for the client, and the
// reason why no certificate was found when it returns nil.
// When requireClientSupport is true, the certificate must be accepted by the
// client, as advertised in the ClientHello.
func (c *CertificateStore) getBestCertificate(clientHello *tls.ClientHelloInfo, requireClientSupport bool) (*CertificateData, string) {
	if c == nil {
		return nil, reasonNoCertificateForName
	}

	serverName := strings.ToLower(strings.TrimSpace(clientHello.ServerName))
	if len(serverName) == 0 {
		// If no ServerName is provided, Check for local IP address matches
		host, _, err := net.SplitHostPort(clientHello.Conn.LocalAddr().String())
		if err != nil {
			log.Debug().Err(err).Msg("Could not split host/port")
		}
		serverName = strings.TrimSpace(host)
	}

	set := c.dynamicCertificates()

	// Only the name-based part of the selection is cached: what the client accepts
	// depends on its capabilities, and is evaluated for every handshake, so that a
	// certificate selected for one client is never served to another one.
	cacheKey := "names\x00" + serverName + "\x00" + strconv.FormatUint(set.generation, 10)

	candidates := set.candidates(serverName)
	if item, ok := c.cachedCandidates(cacheKey); ok {
		candidates = item
	} else if c.CertCache != nil {
		c.CertCache.SetDefault(cacheKey, candidates)
	}

	if len(candidates) == 0 {
		return nil, reasonNoCertificateForName
	}

	for _, candidate := range candidates {
		if requireClientSupport && !certificateUsableByClient(clientHello, candidate.entry.data.Certificate) {
			continue
		}

		c.applyStaple(candidate.entry.data)

		return candidate.entry.data, ""
	}

	return nil, reasonNoAcceptableCertificate
}

// cachedCandidates returns the certificates matching a server name stored under
// the given cache key.
func (c *CertificateStore) cachedCandidates(cacheKey string) ([]certificateCandidate, bool) {
	if c.CertCache == nil {
		return nil, false
	}

	item, ok := c.CertCache.Get(cacheKey)
	if !ok {
		return nil, false
	}

	candidates, ok := item.([]certificateCandidate)

	return candidates, ok
}

// applyStaple sets the OCSP staple of the certificate, if one is available.
func (c *CertificateStore) applyStaple(certificateData *CertificateData) {
	if c.ocspStapler == nil || certificateData == nil || certificateData.Hash == "" {
		return
	}

	// We are updating the OCSPStaple of the certificate without any synchronization
	// as this should not cause any issue.
	if staple, ok := c.ocspStapler.GetStaple(certificateData.Hash); ok {
		certificateData.Certificate.OCSPStaple = staple
	}
}

func (c *CertificateStore) getDefaultCertificateDomains() []string {
	if c.DefaultCertificate == nil {
		return nil
	}

	defaultCert := c.DefaultCertificate.Certificate.Leaf

	var allCerts []string
	if len(defaultCert.Subject.CommonName) > 0 {
		allCerts = append(allCerts, defaultCert.Subject.CommonName)
	}

	allCerts = append(allCerts, defaultCert.DNSNames...)

	for _, ipSan := range defaultCert.IPAddresses {
		allCerts = append(allCerts, ipSan.String())
	}

	return allCerts
}

// certificateStoreBuilder accumulates the certificates of a store, in
// configuration order, while a configuration update is being applied.
type certificateStoreBuilder struct {
	entries []*certificateEntry
	// seen holds the fingerprints of the certificates already added, so that
	// only certificates with the exact same content are skipped.
	seen map[string]struct{}
}

// add appends a certificate to the store being built.
// Certificates sharing the same names are all kept, only duplicates of the same
// certificate content are skipped.
func (b *certificateStoreBuilder) add(storeName string, certificateData *CertificateData, subjectAltNames []string) {
	// Guarantees the order to produce a unique cert key.
	slices.Sort(subjectAltNames)
	domainsKey := strings.Join(subjectAltNames, ",")

	fingerprint := certificateFingerprint(certificateData.Certificate)
	if _, ok := b.seen[fingerprint]; ok {
		log.Debug().Msgf("Skipping addition of certificate for domain(s) %q, to TLS Store %s, as the same certificate content already exists for this store.", domainsKey, storeName)
		return
	}

	if b.seen == nil {
		b.seen = make(map[string]struct{})
	}
	b.seen[fingerprint] = struct{}{}

	log.Debug().Msgf("Adding certificate for domain(s) %s", domainsKey)

	b.entries = append(b.entries, &certificateEntry{
		data:        certificateData,
		domains:     subjectAltNames,
		domainsKey:  domainsKey,
		fingerprint: fingerprint,
	})
}

// set returns the immutable set of the certificates added so far.
func (b *certificateStoreBuilder) set() *certificateSet {
	if b == nil {
		return &certificateSet{}
	}

	return &certificateSet{entries: b.entries}
}

// certificateFingerprint returns a stable identifier for the certificate
// content, covering the whole chain.
func certificateFingerprint(cert *tls.Certificate) string {
	hasher := sha256.New()
	for _, der := range cert.Certificate {
		_, _ = hasher.Write(der)
	}

	return hex.EncodeToString(hasher.Sum(nil))
}

func parseCertificate(cert *Certificate) (tls.Certificate, []string, error) {
	certContent, err := cert.CertFile.Read()
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("unable to read CertFile: %w", err)
	}

	keyContent, err := cert.KeyFile.Read()
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("unable to read KeyFile: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certContent, keyContent)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("unable to generate TLS certificate: %w", err)
	}

	var SANs []string
	if tlsCert.Leaf.Subject.CommonName != "" {
		SANs = append(SANs, strings.ToLower(tlsCert.Leaf.Subject.CommonName))
	}
	if tlsCert.Leaf.DNSNames != nil {
		for _, dnsName := range tlsCert.Leaf.DNSNames {
			if dnsName != tlsCert.Leaf.Subject.CommonName {
				SANs = append(SANs, strings.ToLower(dnsName))
			}
		}
	}
	if tlsCert.Leaf.IPAddresses != nil {
		for _, ip := range tlsCert.Leaf.IPAddresses {
			if ip.String() != tlsCert.Leaf.Subject.CommonName {
				SANs = append(SANs, strings.ToLower(ip.String()))
			}
		}
	}

	return tlsCert, SANs, err
}

// matchDomain returns whether the server name matches one of the cert domains,
// and whether that match is exact or a wildcard match.
// The server name, from TLS SNI, must not have trailing dots (https://datatracker.ietf.org/doc/html/rfc6066#section-3).
// This is enforced by https://github.com/golang/go/blob/d3d7998756c33f69706488cade1cd2b9b10a4c7f/src/crypto/tls/handshake_messages.go#L423-L427.
func matchDomain(serverName string, certDomains []string) (exact bool, ok bool) {
	labels := strings.Split(serverName, ".")
	labels[0] = "*"
	wildcardName := strings.Join(labels, ".")

	for _, certDomain := range certDomains {
		// TODO: assert equality after removing the trailing dots?
		if serverName == certDomain {
			return true, true
		}

		for len(certDomain) > 0 && certDomain[len(certDomain)-1] == '.' {
			certDomain = certDomain[:len(certDomain)-1]
		}

		if certDomain == wildcardName {
			return false, true
		}
	}

	return false, false
}
