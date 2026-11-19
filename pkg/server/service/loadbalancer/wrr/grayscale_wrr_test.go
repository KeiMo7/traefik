package wrr

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
)

// TestBalancerWeightDistributionLargeSample asserts that over a large number of
// requests the share received by each version converges to its configured
// weight, which is the core accuracy requirement of weighted canary rollout.
func TestBalancerWeightDistributionLargeSample(t *testing.T) {
	// Weights 80 / 15 / 5 over 3 versions, with a number of requests that is a
	// multiple of the total weight so the EDF schedule lands on exact counts.
	const requests = 10000
	weights := map[string]int{"v1": 80, "v2": 15, "v3": 5}

	balancer := New(nil, false)
	for name, w := range weights {
		balancer.Add(name, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
			rw.Header().Set("server", name)
			rw.WriteHeader(http.StatusOK)
		}), &w, false)
	}

	recorder := &responseRecorder{ResponseRecorder: httptest.NewRecorder(), save: map[string]int{}}
	for range requests {
		recorder.ResponseRecorder = httptest.NewRecorder()
		balancer.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	}

	for name, w := range weights {
		expected := requests * w / 100
		assert.Equal(t, expected, recorder.save[name], "version %q share must match its weight %d/100", name, w)
	}
	assert.Equal(t, requests, sum(recorder.save))
}

// TestBalancerStickyReassignedWhenBackendDown asserts that a session pinned to a
// backend that becomes unhealthy is transparently reassigned to a healthy one,
// instead of failing on every subsequent request.
func TestBalancerStickyReassignedWhenBackendDown(t *testing.T) {
	balancer := New(&dynamic.Sticky{Cookie: &dynamic.Cookie{Name: "sticky"}}, false)

	balancer.Add("v1", http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("server", "v1")
		rw.WriteHeader(http.StatusOK)
	}), new(1), false)
	balancer.Add("v2", http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("server", "v2")
		rw.WriteHeader(http.StatusOK)
	}), new(1), false)

	// First call pins the session to whichever version WRR picks first.
	recorder := &responseRecorder{ResponseRecorder: httptest.NewRecorder(), save: map[string]int{}, cookies: map[string]*http.Cookie{}}
	balancer.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Len(t, recorder.Result().Cookies(), 1)
	pinnedCookie := recorder.Result().Cookies()[0]

	pinned := recorder.sequence[0]
	other := "v1"
	if pinned == "v1" {
		other = "v2"
	}

	// The pinned version goes down: the sticky cookie must be ignored and the
	// session reassigned to the surviving version.
	balancer.SetStatus(context.Background(), pinned, false)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(pinnedCookie)
	recorder = &responseRecorder{ResponseRecorder: httptest.NewRecorder(), save: map[string]int{}, cookies: map[string]*http.Cookie{}}
	for range 3 {
		recorder.ResponseRecorder = httptest.NewRecorder()
		balancer.ServeHTTP(recorder, req)
	}

	assert.Equal(t, 0, recorder.save[pinned], "no traffic must go to the unhealthy pinned version")
	assert.Equal(t, 3, recorder.save[other], "the session must be reassigned to the healthy version")

	// When the pinned version recovers, the existing cookie sticks to it again.
	balancer.SetStatus(context.Background(), pinned, true)
	recorder = &responseRecorder{ResponseRecorder: httptest.NewRecorder(), save: map[string]int{}, cookies: map[string]*http.Cookie{}}
	balancer.ServeHTTP(recorder, req)
	assert.Equal(t, 1, recorder.save[pinned])
}

func sum(values map[string]int) int {
	var total int
	for _, v := range values {
		total += v
	}
	return total
}
