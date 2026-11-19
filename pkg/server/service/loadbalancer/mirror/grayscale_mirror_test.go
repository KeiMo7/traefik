package mirror

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/safe"
)

// TestMirroredRequestHeader asserts that every request reaching a mirror
// carries the source marker header, while the main request does not.
func TestMirroredRequestHeader(t *testing.T) {
	results := make(chan string, 1)

	mainHandler := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	pool := safe.NewPool(t.Context())
	mirroring := New(mainHandler, pool, true, defaultMaxBodySize, false, nil)

	require.NoError(t, mirroring.AddMirror("shadow", http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		results <- req.Header.Get(HeaderMirroredRequest)
	}), 100, 100))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	recorder := httptest.NewRecorder()
	mirroring.ServeHTTP(recorder, req)

	require.Equal(t, "true", <-results)
	pool.Stop()

	// The source marker must only be added to the mirrored copy.
	assert.NotEqual(t, "true", req.Header.Get(HeaderMirroredRequest))
	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
}

// TestMirroredRequestHeader_streamBody asserts the marker is also set on the
// streamed variant of the mirrored requests.
func TestMirroredRequestHeader_streamBody(t *testing.T) {
	results := make(chan string, 1)

	mainHandler := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	pool := safe.NewPool(t.Context())
	mirroring := New(mainHandler, pool, true, defaultMaxBodySize, true, nil)

	require.NoError(t, mirroring.AddMirror("shadow", http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		results <- req.Header.Get(HeaderMirroredRequest)
	}), 100, 100))

	mirroring.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, "true", <-results)
	pool.Stop()
}

// TestUnhealthyMirrorIsSkipped asserts that a mirror reported as down stops
// receiving requests, the main handler keeps answering, and a recovered mirror
// resumes receiving its configured fraction without a catch-up burst.
func TestUnhealthyMirrorIsSkipped(t *testing.T) {
	var mainCount, mirrorCount atomic.Int32

	mainHandler := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		mainCount.Add(1)
		rw.WriteHeader(http.StatusOK)
	})
	pool := safe.NewPool(t.Context())
	mirroring := New(mainHandler, pool, true, defaultMaxBodySize, false, nil)

	require.NoError(t, mirroring.AddMirror("shadow", http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		mirrorCount.Add(1)
		rw.WriteHeader(http.StatusOK)
	}), 100, 100))

	// While the mirror is down, all requests must still reach the main handler
	// and none must reach the mirror.
	mirroring.SetMirrorStatus(t.Context(), "shadow", false)
	for range 20 {
		mirroring.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}

	assert.Equal(t, int32(20), mainCount.Load())
	assert.Equal(t, int32(0), mirrorCount.Load())

	// After recovery, the virtual counter has advanced with the missed requests,
	// so the mirror must not catch up on the 20 requests it missed.
	mirroring.SetMirrorStatus(t.Context(), "shadow", true)
	for range 10 {
		mirroring.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}
	pool.Stop()

	assert.Equal(t, int32(30), mainCount.Load())
	assert.Equal(t, int32(10), mirrorCount.Load())
}

// TestAllMirrorsDownDoesNotFailMain asserts that with every mirror down the
// mirroring handler behaves exactly like the main handler.
func TestAllMirrorsDownDoesNotFailMain(t *testing.T) {
	var mirrorCount atomic.Int32

	pool := safe.NewPool(t.Context())
	mirroring := New(
		http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusAccepted) }),
		pool, true, defaultMaxBodySize, false, nil,
	)
	require.NoError(t, mirroring.AddMirror("shadow-1", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mirrorCount.Add(1)
	}), 50, 100))
	require.NoError(t, mirroring.AddMirror("shadow-2", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mirrorCount.Add(1)
	}), 50, 100))

	mirroring.SetMirrorStatus(t.Context(), "shadow-1", false)
	mirroring.SetMirrorStatus(t.Context(), "shadow-2", false)

	for range 20 {
		recorder := httptest.NewRecorder()
		mirroring.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusAccepted, recorder.Result().StatusCode)
	}
	pool.Stop()

	assert.Equal(t, int32(0), mirrorCount.Load())
}

// TestSlowMirrorDoesNotSlowMainRequest asserts that a mirror hanging well beyond
// the main handler's response time never delays the main response, and that the
// mirror goroutine is reaped by the routine pool without affecting the client.
func TestSlowMirrorDoesNotSlowMainRequest(t *testing.T) {
	released := make(chan struct{})
	var mirrorStarted atomic.Bool

	pool := safe.NewPool(t.Context())
	mirroring := New(
		http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) }),
		pool, true, defaultMaxBodySize, false, nil,
	)
	require.NoError(t, mirroring.AddMirror("slow-shadow", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mirrorStarted.Store(true)
		// Block until the test releases the shadow, simulating a very slow backend.
		<-released
	}), 100, 100))

	startedAt := time.Now()
	recorder := httptest.NewRecorder()
	mirroring.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	mainElapsed := time.Since(startedAt)

	assert.Equal(t, http.StatusOK, recorder.Result().StatusCode)
	assert.Less(t, mainElapsed, 100*time.Millisecond,
		"the main request must not wait on a slow mirror (took %s)", mainElapsed)

	// The mirror must have been invoked asynchronously, then be allowed to finish.
	require.Eventually(t, mirrorStarted.Load, time.Second, 10*time.Millisecond)
	close(released)
	pool.Stop()
}
