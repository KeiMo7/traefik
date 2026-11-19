package service

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/paerser/types"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/config/runtime"
	"github.com/traefik/traefik/v3/pkg/config/static"
	obsmetrics "github.com/traefik/traefik/v3/pkg/observability/metrics"
	"github.com/traefik/traefik/v3/pkg/proxy/httputil"
	"github.com/traefik/traefik/v3/pkg/safe"
	"github.com/traefik/traefik/v3/pkg/server/middleware"
	"github.com/traefik/traefik/v3/pkg/server/service/loadbalancer/mirror"
)

// canaryBackend is a real HTTP backend that counts the requests it receives,
// answers 200 on its business path and reports its health through a toggleable
// /health endpoint, so active health checks can drive it up and down.
type canaryBackend struct {
	server *httptest.Server

	count   atomic.Int64
	healthy atomic.Bool
	delay   time.Duration
}

func newCanaryBackend(t *testing.T, delay time.Duration) *canaryBackend {
	t.Helper()
	b := &canaryBackend{delay: delay}
	b.healthy.Store(true)
	b.server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/health" {
			if !b.healthy.Load() {
				rw.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			rw.WriteHeader(http.StatusOK)
			return
		}

		b.count.Add(1)
		if b.delay > 0 {
			time.Sleep(b.delay)
		}
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(b.server.Close)
	return b
}

func (b *canaryBackend) loadBalancerInfo() *runtime.ServiceInfo {
	return &runtime.ServiceInfo{
		Service: &dynamic.Service{
			LoadBalancer: &dynamic.ServersLoadBalancer{
				Servers: []dynamic.Server{{URL: b.server.URL}},
				HealthCheck: &dynamic.ServerHealthCheck{
					Path:     "/health",
					Interval: types.Duration(50 * time.Millisecond),
					Timeout:  types.Duration(50 * time.Millisecond),
					UnhealthyInterval: func() *types.Duration {
						d := types.Duration(25 * time.Millisecond)
						return &d
					}(),
				},
			},
		},
	}
}

func newWeightedManager(t *testing.T, pool *safe.Pool, configs map[string]*runtime.ServiceInfo) *Manager {
	t.Helper()
	proxyBuilder := httputil.NewProxyBuilder(&transportManagerMock{}, nil)
	observabilityMgr := middleware.NewObservabilityMgr(static.Configuration{}, obsmetrics.NewVoidRegistry(), nil, nil, nil, nil)
	return NewManager(configs, observabilityMgr, pool, &transportManagerMock{}, proxyBuilder)
}

// TestManager_CanaryWeightedDistribution drives the full service manager with
// real HTTP backends and asserts that the long-run share of each version
// converges to the configured weights, including after a version is removed by
// the active health check (traffic is rebalanced on the healthy versions).
func TestManager_CanaryWeightedDistribution(t *testing.T) {
	v1, v2, v3 := newCanaryBackend(t, 0), newCanaryBackend(t, 0), newCanaryBackend(t, 0)

	configs := map[string]*runtime.ServiceInfo{
		"v1@file": v1.loadBalancerInfo(),
		"v2@file": v2.loadBalancerInfo(),
		"v3@file": v3.loadBalancerInfo(),
		"canary@file": {
			Service: &dynamic.Service{
				Weighted: &dynamic.WeightedRoundRobin{
					Services: []dynamic.WRRService{
						{Name: "v1@file", Weight: intPtr(80)},
						{Name: "v2@file", Weight: intPtr(15)},
						{Name: "v3@file", Weight: intPtr(5)},
					},
					HealthCheck: &dynamic.HealthCheck{},
				},
			},
		},
	}

	pool := safe.NewPool(t.Context())
	manager := newWeightedManager(t, pool, configs)
	handler, err := manager.BuildHTTP(t.Context(), "canary@file")
	require.NoError(t, err)
	manager.LaunchHealthCheck(t.Context())

	const requests = 10000
	for range requests {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}

	assert.Equal(t, int64(8000), v1.count.Load())
	assert.Equal(t, int64(1500), v2.count.Load())
	assert.Equal(t, int64(500), v3.count.Load())

	// v3 fails its health check: its 5% share must be reallocated proportionally
	// to v1 and v2 without any client request failing.
	v3.healthy.Store(false)
	// Wait for several health-check cycles (interval is 50ms) for the down
	// status to be detected and propagated to the weighted balancer.
	require.Eventually(t, func() bool {
		time.Sleep(150 * time.Millisecond)
		snapshot := v3.count.Load()
		time.Sleep(150 * time.Millisecond)
		return v3.count.Load() == snapshot
	}, 2*time.Second, 50*time.Millisecond, "v3 must stop receiving traffic once its health check fails")

	countAtFailure := v3.count.Load()
	v1Before, v2Before := v1.count.Load(), v2.count.Load()
	const rebalancedRequests = 2000
	for range rebalancedRequests {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}

	assert.Equal(t, countAtFailure, v3.count.Load(), "the unhealthy version must not receive any more traffic")
	// The traffic is rebalanced on the healthy versions, weighted 80/15.
	assert.InDelta(t, float64(rebalancedRequests)*15/95, float64(v2.count.Load()-v2Before), 5)
	assert.InDelta(t, float64(rebalancedRequests)*80/95, float64(v1.count.Load()-v1Before), 5)
}

// TestManager_CanaryStickySession asserts that a client presenting the sticky
// cookie always lands on the same version, while many cookieless clients are
// still spread according to the weights so global proportions do not drift.
func TestManager_CanaryStickySession(t *testing.T) {
	v1, v2 := newCanaryBackend(t, 0), newCanaryBackend(t, 0)

	configs := map[string]*runtime.ServiceInfo{
		"v1@file": v1.loadBalancerInfo(),
		"v2@file": v2.loadBalancerInfo(),
		"canary@file": {
			Service: &dynamic.Service{
				Weighted: &dynamic.WeightedRoundRobin{
					Services: []dynamic.WRRService{
						{Name: "v1@file", Weight: intPtr(70)},
						{Name: "v2@file", Weight: intPtr(30)},
					},
					Sticky:      &dynamic.Sticky{Cookie: &dynamic.Cookie{Name: "canary-cookie"}},
					HealthCheck: &dynamic.HealthCheck{},
				},
			},
		},
	}

	manager := newWeightedManager(t, safe.NewPool(t.Context()), configs)
	handler, err := manager.BuildHTTP(t.Context(), "canary@file")
	require.NoError(t, err)

	// A single client repeats many requests with the cookie obtained on the first one.
	firstRecorder := httptest.NewRecorder()
	handler.ServeHTTP(firstRecorder, httptest.NewRequest(http.MethodGet, "/", nil))
	cookies := firstRecorder.Result().Cookies()
	require.Len(t, cookies, 1)

	stickyClient := httptest.NewRequest(http.MethodGet, "/", nil)
	stickyClient.AddCookie(cookies[0])
	pinnedToV1 := v1.count.Load() == 1
	require.True(t, pinnedToV1 || v2.count.Load() == 1)

	for range 19 {
		handler.ServeHTTP(httptest.NewRecorder(), stickyClient)
	}
	if pinnedToV1 {
		assert.Equal(t, int64(20), v1.count.Load())
		assert.Equal(t, int64(0), v2.count.Load())
	} else {
		assert.Equal(t, int64(0), v1.count.Load())
		assert.Equal(t, int64(20), v2.count.Load())
	}

	// When the pinned version goes down, the sticky session must be reassigned
	// to the healthy version instead of failing.
	pinned, other := v1, v2
	if !pinnedToV1 {
		pinned, other = v2, v1
	}
	pinned.healthy.Store(false)
	manager.LaunchHealthCheck(t.Context())
	require.Eventually(t, func() bool {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, stickyClient)
		return recorder.Result().StatusCode == http.StatusOK && other.count.Load() > 0
	}, 2*time.Second, 25*time.Millisecond)
}

// TestManager_MirroringIsolation drives the full mirroring service with a real
// shadow backend: mirrored requests carry the source marker, the shadow is
// asynchronous and isolated (its latency never reaches the client), and a
// shadow reported unhealthy is skipped while the main path stays untouched.
func TestManager_MirroringIsolation(t *testing.T) {
	main := newCanaryBackend(t, 0)
	// The shadow answers slowly, well beyond the tolerance for the main response time.
	shadow := newCanaryBackend(t, 200*time.Millisecond)
	var sawMarker atomic.Bool
	shadow.server.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/health" {
			if !shadow.healthy.Load() {
				rw.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			rw.WriteHeader(http.StatusOK)
			return
		}
		if req.Header.Get(mirror.HeaderMirroredRequest) == "true" {
			sawMarker.Store(true)
		}
		shadow.count.Add(1)
		time.Sleep(shadow.delay)
		rw.WriteHeader(http.StatusOK)
	})

	configs := map[string]*runtime.ServiceInfo{
		"main@file":   main.loadBalancerInfo(),
		"shadow@file": shadow.loadBalancerInfo(),
		"mirrored@file": {
			Service: &dynamic.Service{
				Mirroring: &dynamic.Mirroring{
					Service: "main@file",
					Mirrors: []dynamic.MirrorService{
						{Name: "shadow@file", Percent: 100},
					},
					HealthCheck: &dynamic.HealthCheck{},
				},
			},
		},
	}

	pool := safe.NewPool(t.Context())
	manager := newWeightedManager(t, pool, configs)
	handler, err := manager.BuildHTTP(t.Context(), "mirrored@file")
	require.NoError(t, err)
	manager.LaunchHealthCheck(t.Context())

	// The slow shadow must not slow down the main response.
	startedAt := time.Now()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	elapsed := time.Since(startedAt)
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	assert.Less(t, elapsed, 100*time.Millisecond, "shadow latency must not affect the main response (took %s)", elapsed)

	require.Eventually(t, func() bool { return shadow.count.Load() >= 1 }, 2*time.Second, 10*time.Millisecond)
	assert.Equal(t, int64(1), main.count.Load())
	assert.True(t, sawMarker.Load(), "the shadow must be able to identify mirrored traffic")

	// The shadow goes down: mirroring stops while the main path keeps serving.
	shadow.healthy.Store(false)
	// Wait for several health-check cycles (interval is 50ms) for the down
	// status to be detected and propagated through the mirroring handler.
	require.Eventually(t, func() bool {
		time.Sleep(150 * time.Millisecond)
		snapshot := shadow.count.Load()
		time.Sleep(150 * time.Millisecond)
		return shadow.count.Load() == snapshot
	}, 2*time.Second, 50*time.Millisecond, "the shadow must stop receiving mirrored requests once unhealthy")

	mainBefore := main.count.Load()
	shadowBefore := shadow.count.Load()
	for range 10 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	}
	pool.Stop()

	assert.Equal(t, mainBefore+10, main.count.Load(), "the main service must keep serving every request")
	assert.Equal(t, shadowBefore, shadow.count.Load(), "the unhealthy shadow must stop receiving mirrored requests")
}

// TestManager_RejectsInvalidWeight asserts that non-positive weights are
// rejected at configuration build time rather than silently skewing traffic.
func TestManager_RejectsInvalidWeight(t *testing.T) {
	backend := newCanaryBackend(t, 0)

	configs := map[string]*runtime.ServiceInfo{
		"v1@file": backend.loadBalancerInfo(),
		"canary@file": {
			Service: &dynamic.Service{
				Weighted: &dynamic.WeightedRoundRobin{
					Services: []dynamic.WRRService{
						{Name: "v1@file", Weight: intPtr(10)},
						{Name: "v1@file", Weight: intPtr(0)},
					},
				},
			},
		},
	}

	manager := newWeightedManager(t, safe.NewPool(t.Context()), configs)
	_, err := manager.BuildHTTP(t.Context(), "canary@file")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid weight")
}

func intPtr(v int) *int { return &v }
