package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newStatefulSDKHandler builds the same stateful SDK handler the gateway uses for
// routed servers (see buildMCPHandler), exposing one tool so tools/list has content.
func newStatefulSDKHandler(t *testing.T) http.Handler {
	t.Helper()
	server := sdk.NewServer(&sdk.Implementation{Name: "safeoutputs", Version: "1.0"}, nil)
	sdk.AddTool(server, &sdk.Tool{
		Name:        "create_issue",
		Description: "stage an issue",
	}, func(context.Context, *sdk.CallToolRequest, map[string]any) (*sdk.CallToolResult, any, error) {
		return &sdk.CallToolResult{}, nil, nil
	})
	return sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return server },
		&sdk.StreamableHTTPOptions{Stateless: false, JSONResponse: true})
}

func postJSONRPC(handler http.Handler, protocolVersion, sessionID, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/mcp/safeoutputs", strings.NewReader(body))
	req.Header.Set("Authorization", "test-api-key")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if protocolVersion != "" {
		req.Header.Set(mcpProtocolVersionHeader, protocolVersion)
	}
	// SEP-2575 clients send the standard Mcp-Method header alongside the body.
	var rpc struct {
		Method string `json:"method"`
	}
	if json.Unmarshal([]byte(body), &rpc) == nil && rpc.Method != "" {
		req.Header.Set("Mcp-Method", rpc.Method)
	}
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// Bodies mirroring the Copilot CLI sequence observed in MovementAtlas pilot runs
// 35582436793 and 35592921190 against the routed safeoutputs endpoint.
const (
	liveDiscoverBody = `{"jsonrpc":"2.0","id":0,"method":"server/discover","params":{"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
		`"io.modelcontextprotocol/clientCapabilities":{},` +
		`"io.modelcontextprotocol/clientInfo":{"name":"copilot","version":"1.0"}}}}`
	liveSessionlessToolsListBody = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{` +
		`"io.modelcontextprotocol/protocolVersion":"2025-11-25",` +
		`"io.modelcontextprotocol/clientCapabilities":{}}}}`
	legacyInitializeBody  = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"copilot","version":"1.0"}}}`
	legacyInitializedBody = `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`
	legacyToolsListBody   = `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
)

// TestStatefulSDK_DiscoverThenSessionlessToolsListIsRejected documents the SDK
// behaviour behind the live defect: a stateful StreamableHTTPHandler answers
// server/discover with 200 and no Mcp-Session-Id, and then rejects the
// sessionless tools/list that follows with JSON-RPC -32022. Auto-init cannot
// repair that second request by injecting a session: the rejection keys off the
// per-request _meta protocol version, not the missing session.
func TestStatefulSDK_DiscoverThenSessionlessToolsListIsRejected(t *testing.T) {
	handler := newStatefulSDKHandler(t)

	disc := postJSONRPC(handler, "2026-07-28", "", liveDiscoverBody)
	require.Equal(t, http.StatusOK, disc.Code, disc.Body.String())
	assert.Empty(t, disc.Header().Get("Mcp-Session-Id"), "raw SDK discover reply carries no session")

	list := postJSONRPC(handler, "2025-11-25", "", liveSessionlessToolsListBody)
	var resp struct {
		Error *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(list.Body.Bytes(), &resp), list.Body.String())
	require.NotNil(t, resp.Error)
	assert.Equal(t, -32022, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, `protocol version "2025-11-25" is not supported`)
}

// TestWrapWithSessionAutoInit_StatefulDiscoverForcesLegacyHandshake is the
// regression for the live defect. Through the gateway wrapper, server/discover on
// the stateful handler must be refused with a non-2xx response (as the
// ci-evidence route already does via the evidence boundary), so a SEP-2575
// client falls back to the legacy initialize handshake, obtains a session, and
// tools/list returns the catalog.
func TestWrapWithSessionAutoInit_StatefulDiscoverForcesLegacyHandshake(t *testing.T) {
	handler := WrapWithSessionAutoInit(newStatefulSDKHandler(t))

	disc := postJSONRPC(handler, "2026-07-28", "", liveDiscoverBody)
	assert.Equal(t, http.StatusBadRequest, disc.Code, "discover must be refused so the client falls back to initialize; body=%s", disc.Body.String())
	assert.Empty(t, disc.Header().Get("Mcp-Session-Id"))

	// Client fallback: legacy initialize handshake.
	initResp := postJSONRPC(handler, "", "", legacyInitializeBody)
	require.Equal(t, http.StatusOK, initResp.Code, initResp.Body.String())
	sessionID := initResp.Header().Get("Mcp-Session-Id")
	require.NotEmpty(t, sessionID)
	initd := postJSONRPC(handler, "2025-11-25", sessionID, legacyInitializedBody)
	require.Equal(t, http.StatusAccepted, initd.Code, initd.Body.String())

	list := postJSONRPC(handler, "2025-11-25", sessionID, legacyToolsListBody)
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	var resp struct {
		Error  *json.RawMessage `json:"error"`
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(list.Body.Bytes(), &resp), list.Body.String())
	require.Nil(t, resp.Error, list.Body.String())
	require.Len(t, resp.Result.Tools, 1)
	assert.Equal(t, "create_issue", resp.Result.Tools[0].Name)
}

// TestWrapWithSessionAutoInit_DiscoverRefusalSitsBehindAuth verifies that the
// discover refusal does not weaken authentication: in the real stack the auth
// middleware is outside the wrapper, so an unauthenticated discover is rejected
// with 401 before the wrapper (or the SDK) sees it, and an authenticated one
// still receives the 400 fallback signal without reaching the SDK handler.
func TestWrapWithSessionAutoInit_DiscoverRefusalSitsBehindAuth(t *testing.T) {
	var innerCalls int
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerCalls++
		w.WriteHeader(http.StatusOK)
	})
	handler := authMiddleware([]string{"secret-key"}, WrapWithSessionAutoInit(inner).ServeHTTP)

	unauth := httptest.NewRequest(http.MethodPost, "/mcp/safeoutputs", strings.NewReader(liveDiscoverBody))
	unauth.Header.Set("Content-Type", "application/json")
	unauth.Header.Set("Accept", "application/json, text/event-stream")
	unauth.Header.Set(mcpProtocolVersionHeader, "2026-07-28")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, unauth)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, 0, innerCalls)

	authed := httptest.NewRequest(http.MethodPost, "/mcp/safeoutputs", strings.NewReader(liveDiscoverBody))
	authed.Header.Set("Authorization", "secret-key")
	authed.Header.Set("Content-Type", "application/json")
	authed.Header.Set("Accept", "application/json, text/event-stream")
	authed.Header.Set(mcpProtocolVersionHeader, "2026-07-28")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, authed)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, 0, innerCalls, "refused discover must not reach the SDK handler")
}

// TestWrapWithSessionAutoInit_DiscoverWithSessionPassesThrough verifies the
// discover refusal is scoped to session-less requests only: anything carrying an
// established Mcp-Session-Id is forwarded unchanged, as before.
func TestWrapWithSessionAutoInit_DiscoverWithSessionPassesThrough(t *testing.T) {
	var handlerCalls int
	handler := WrapWithSessionAutoInit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalls++
		w.WriteHeader(http.StatusOK)
	}))
	w := postJSONRPC(handler, "2026-07-28", "existing-session", liveDiscoverBody)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 1, handlerCalls)
}
