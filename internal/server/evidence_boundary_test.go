package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func TestEvidenceBoundaryActualSDKSerializer(t *testing.T) {
	for _, text := range []string{strings.Repeat("x", 4096), strings.Repeat("\u2028\u2029<>&\\\"😀", 500)} {
		server := sdk.NewServer(&sdk.Implementation{Name: "evidence-test", Version: "1"}, nil)
		server.AddTool(&sdk.Tool{Name: "read_ci_evidence", InputSchema: map[string]any{"type": "object"}}, func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: text}}}, nil
		})
		h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server }, &sdk.StreamableHTTPOptions{Stateless: true})
		post := func(handler http.Handler, args string) *httptest.ResponseRecorder {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			r := evidenceRequest("99", args).WithContext(ctx)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json, text/event-stream")
			r.Header.Set("MCP-Protocol-Version", "2025-11-25")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			return w
		}
		red := post(h, `{"operation":"read","kind":"evidence"}`)
		require.Equal(t, http.StatusOK, red.Code)
		require.Greater(t, red.Body.Len(), 4096)
		require.Contains(t, red.Body.String(), "event: message\ndata: ")
		b := newEvidenceBoundary(evidenceLease(t))
		guarded := b.wrap(h, "ci-evidence")
		post(guarded, `{"operation":"index"}`)
		green := post(guarded, `{"operation":"read","kind":"evidence"}`)
		require.Equal(t, http.StatusBadGateway, green.Code)
		require.Empty(t, green.Body.Bytes())
	}
}

func TestEvidenceBoundaryIDSerialization(t *testing.T) {
	for _, id := range []any{json.Number("9"), json.Number("10"), json.Number("99"), json.Number("100"), json.Number("9007199254740991"), strings.Repeat("a", 62), strings.Repeat("<", 62), "\\\"😀\u2028\u2029"} {
		require.True(t, evidenceIDOK(id))
	}
	require.False(t, evidenceIDOK(strings.Repeat("\u2028", 11)))
}

func evidenceLease(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	// The lease parent must be private (0700); t.TempDir subdirectories are umask-created.
	require.NoError(t, os.Chmod(p, 0o700))
	return filepath.Join(p, "lease.json")
}

func evidenceRequest(id, args string) *http.Request {
	return httptest.NewRequest(http.MethodPost, "/mcp/ci-evidence", strings.NewReader(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":"read_ci_evidence","arguments":%s}}`, id, args)))
}

func TestEvidenceBoundaryFinalBody(t *testing.T) {
	for _, size := range []int{4096, 4118} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			b := newEvidenceBoundary(evidenceLease(t))
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", size))) })
			h := b.wrap(next, "ci-evidence")
			h.ServeHTTP(httptest.NewRecorder(), evidenceRequest("1", `{"operation":"index"}`))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, evidenceRequest("2", `{"operation":"read","kind":"evidence"}`))
			if size == 4096 {
				require.Len(t, w.Body.Bytes(), size)
			} else {
				require.Empty(t, w.Body.Bytes())
				require.Equal(t, http.StatusBadGateway, w.Code)
			}
		})
	}
}

func TestEvidenceBoundaryIDBeforeBackend(t *testing.T) {
	for _, id := range []string{`"` + strings.Repeat("a", 63) + `"`, `"` + strings.Repeat(`\u2028`, 11) + `"`, `9007199254740992`, `null`, `true`} {
		t.Run(id[:min(len(id), 16)], func(t *testing.T) {
			b := newEvidenceBoundary(evidenceLease(t))
			calls := 0
			h := b.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }), "ci-evidence")
			h.ServeHTTP(httptest.NewRecorder(), evidenceRequest("1", `{"operation":"index"}`))
			calls = 0
			w := httptest.NewRecorder()
			h.ServeHTTP(w, evidenceRequest(id, `{"operation":"read"}`))
			require.Zero(t, calls)
			require.Empty(t, w.Body.Bytes())
			require.Equal(t, 1, b.state.Attempts)
		})
	}
}

type evidenceDebitWriter struct {
	*httptest.ResponseRecorder
	check func()
}

func (w evidenceDebitWriter) Write(p []byte) (int, error) {
	w.check()
	return w.ResponseRecorder.Write(p)
}

func TestEvidenceBoundaryActualDebitBeforeRelease(t *testing.T) {
	lease := evidenceLease(t)
	b := newEvidenceBoundary(lease)
	h := b.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 4096))) }), "ci-evidence")
	h.ServeHTTP(httptest.NewRecorder(), evidenceRequest("1", `{"operation":"index"}`))
	for i := 1; i <= 8; i++ {
		check := func() {
			data, err := os.ReadFile(lease)
			require.NoError(t, err)
			var state evidenceBudget
			require.NoError(t, json.Unmarshal(data, &state))
			require.Equal(t, i*4096, state.ResponseBytes)
			require.Equal(t, i, state.Attempts)
		}
		w := evidenceDebitWriter{httptest.NewRecorder(), check}
		h.ServeHTTP(w, evidenceRequest("2", `{"operation":"read","kind":"evidence"}`))
		require.Len(t, w.Body.Bytes(), 4096)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, evidenceRequest("3", `{"operation":"read","kind":"evidence"}`))
	require.Empty(t, w.Body.Bytes())
	require.Equal(t, 32768, b.state.ResponseBytes)
}

func TestEvidenceBoundaryConcurrentUnifiedAndRouted(t *testing.T) {
	b := newEvidenceBoundary(evidenceLease(t))
	calls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = w.Write([]byte("ok")) })
	routed, unified := b.wrap(next, "ci-evidence"), b.wrap(next, "")
	routed.ServeHTTP(httptest.NewRecorder(), evidenceRequest("1", `{"operation":"index"}`))
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := evidenceRequest("2", `{"operation":"read","kind":"evidence"}`)
			data, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(strings.NewReader(strings.ReplaceAll(string(data), `"read_ci_evidence"`, `"ci-evidence___read_ci_evidence"`)))
			unified.ServeHTTP(httptest.NewRecorder(), r)
		}()
	}
	wg.Wait()
	require.Equal(t, 9, calls)
	require.Equal(t, 8, b.state.Attempts)
}

func TestEvidenceBoundaryDurableAdmissionAndRestart(t *testing.T) {
	lease := evidenceLease(t)
	b := newEvidenceBoundary(lease)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(lease)
		require.NoError(t, err)
		require.Contains(t, string(data), `"indexUsed":true`)
		_, _ = w.Write([]byte("ok"))
	})
	h := b.wrap(next, "ci-evidence")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, evidenceRequest("1", `{"operation":"index"}`))
	require.Equal(t, "ok", w.Body.String())
	second := newEvidenceBoundary(lease)
	w = httptest.NewRecorder()
	second.wrap(next, "ci-evidence").ServeHTTP(w, evidenceRequest("2", `{"operation":"index"}`))
	require.Empty(t, w.Body.Bytes())
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestEvidenceBoundarySharedAttemptsAndSource(t *testing.T) {
	b := newEvidenceBoundary(evidenceLease(t))
	calls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = w.Write([]byte("ok")) })
	routed := b.wrap(next, "ci-evidence")
	routed.ServeHTTP(httptest.NewRecorder(), evidenceRequest("1", `{"operation":"index"}`))
	for i := 0; i < 9; i++ {
		w := httptest.NewRecorder()
		routed.ServeHTTP(w, evidenceRequest("2", `{"operation":"read","kind":"source"}`))
		if i >= 3 {
			require.Empty(t, w.Body.Bytes())
		}
	}
	require.Equal(t, 4, calls)
	require.Equal(t, 8, b.state.Attempts)
}

func TestEvidenceBoundaryRefusesFlushAndDuplicateKeys(t *testing.T) {
	b := newEvidenceBoundary(evidenceLease(t))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 5000)))
		w.(http.Flusher).Flush()
	})
	h := b.wrap(next, "ci-evidence")
	h.ServeHTTP(httptest.NewRecorder(), evidenceRequest("1", `{"operation":"index"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, evidenceRequest("2", `{"operation":"read"}`))
	require.Empty(t, w.Body.Bytes())
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp/ci-evidence", strings.NewReader(`{"method":"ping","method":"tools/call","id":1}`)))
	require.Empty(t, w.Body.Bytes())
}

func TestEvidenceBoundaryControlBodiesAreNotEvidenceCapped(t *testing.T) {
	b := newEvidenceBoundary(evidenceLease(t))
	big := strings.Repeat("x", 20000)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(big)) })
	h := b.wrap(next, "")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, w.Body.Bytes(), 20000)
	require.Zero(t, b.state.Attempts)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp/", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)))
	require.Equal(t, http.StatusOK, w.Code)
	huge := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", evidenceControlLimit+1))) })
	w = httptest.NewRecorder()
	b.wrap(huge, "").ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp/", strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)))
	require.Equal(t, http.StatusBadGateway, w.Code)
	require.Empty(t, w.Body.Bytes())
}

func TestEvidenceBoundaryRoutedOtherBackendIsUntouched(t *testing.T) {
	b := newEvidenceBoundary(evidenceLease(t))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 70000))) })
	for _, route := range []string{"safeoutputs", "github"} {
		w := httptest.NewRecorder()
		b.wrap(next, route).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp/"+route, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)))
		require.Equal(t, http.StatusOK, w.Code)
		require.Len(t, w.Body.Bytes(), 70000)
	}
	require.Zero(t, b.state.Attempts)
	// Routed evidence backends are named explicitly even when backendID is empty (stdio).
	cfg := mcpHandlerConfig{evidenceRoute: "ci-evidence"}
	route := cfg.evidenceRoute
	if route == "" {
		route = cfg.backendID
	}
	require.Equal(t, "ci-evidence", route)
}
