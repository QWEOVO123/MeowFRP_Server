package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
	"frp-control-server/internal/edgestate"
	"frp-control-server/internal/security"
)

func TestEdgeLocalAdministratorLogin(t *testing.T) {
	hash, err := security.HashPassword("test-password")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Mode: config.ModeEdge, ConfigState: "configured", Initialized: true, CookieSecret: "test-secret", SessionTTL: time.Hour, UDPConnectionTTL: time.Second, InitialAdmin: config.InitialAdminConfig{Username: "edge-admin", DisplayName: "Edge Admin", PasswordHash: hash}}
	server := NewServer(cfg, nil)
	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"edge-admin","password":"test-password"}`))
	login.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, login)
	if recorder.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", recorder.Code, recorder.Body.String())
	}
	result := recorder.Result()
	cookies := result.Cookies()
	if len(cookies) == 0 {
		t.Fatal("expected admin cookie")
	}
	if !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("administrator cookie must be Secure and HttpOnly: %#v", cookies[0])
	}
	me := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	me.AddCookie(cookies[0])
	meRecorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(meRecorder, me)
	if meRecorder.Code != http.StatusOK {
		t.Fatalf("me failed: %d %s", meRecorder.Code, meRecorder.Body.String())
	}
}

func TestDisconnectedEdgeRejectsNewClientAuthentication(t *testing.T) {
	state, err := edgestate.Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	client := cluster.NewEdgeClient("127.0.0.1:1", "node-test", "localhost", cluster.TLSFiles{}, nil)
	server := NewServer(config.Config{Mode: config.ModeEdge, ConfigState: "configured"}, nil, WithEdgeRuntime(state, client))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/client/resource-policy", strings.NewReader(`{"access_token":"ak_test","client_id":"hwid-test"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"status":"node_fault"`) {
		t.Fatalf("unexpected response: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestOnlineCredentialCommandRotatesEdgeAdminAndInvalidatesSession(t *testing.T) {
	hash, err := security.HashPassword("old-password")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Mode: config.ModeEdge, ConfigState: "configured", Initialized: true,
		ConfigPath: filepath.Join(t.TempDir(), "edge.cfg.json"), CookieSecret: "test-secret", SessionTTL: time.Hour,
		InitialAdmin: config.InitialAdminConfig{Username: "old-admin", DisplayName: "Old", PasswordHash: hash},
		Edge:         config.EdgeConfig{ControllerAdministrationEnabled: true},
	}
	server := NewServer(cfg, nil)
	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"old-admin","password":"old-password"}`))
	login.Header.Set("Content-Type", "application/json")
	loginRecorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(loginRecorder, login)
	if loginRecorder.Code != http.StatusOK || len(loginRecorder.Result().Cookies()) == 0 {
		t.Fatalf("initial login failed: %d %s", loginRecorder.Code, loginRecorder.Body.String())
	}
	payload, _ := json.Marshal(map[string]string{"username": "new-admin", "display_name": "New", "password": "new-password"})
	result := server.rotateLocalEdgeAdmin(context.Background(), cluster.NodeCommand{CommandID: "live-1", Command: "rotate_edge_admin", Payload: payload, ExpiresAt: time.Now().Add(time.Second)})
	if result.Status != "succeeded" {
		t.Fatalf("credential rotation failed: %#v", result)
	}
	oldSession := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	oldSession.AddCookie(loginRecorder.Result().Cookies()[0])
	oldSessionRecorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(oldSessionRecorder, oldSession)
	if oldSessionRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("old edge session must be invalidated, got %d", oldSessionRecorder.Code)
	}
	newLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{"username":"new-admin","password":"new-password"}`))
	newLogin.Header.Set("Content-Type", "application/json")
	newLoginRecorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(newLoginRecorder, newLogin)
	if newLoginRecorder.Code != http.StatusOK {
		t.Fatalf("new credentials rejected: %d %s", newLoginRecorder.Code, newLoginRecorder.Body.String())
	}
}

func TestCredentialCommandRequiresLocalControllerAdministrationSwitch(t *testing.T) {
	server := NewServer(config.Config{Mode: config.ModeEdge, ConfigState: "configured"}, nil)
	payload := json.RawMessage(`{"username":"new-admin","password":"new-password"}`)
	result := server.rotateLocalEdgeAdmin(context.Background(), cluster.NodeCommand{CommandID: "live-2", Command: "rotate_edge_admin", Payload: payload})
	if result.Status != "failed" || !strings.Contains(result.Error, "disabled") {
		t.Fatalf("disabled controller administration must reject rotation: %#v", result)
	}
}

func TestEdgeClientCommandAcknowledgementEndpoint(t *testing.T) {
	ctx := context.Background()
	state, err := edgestate.Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	snapshot := cluster.IdentitySnapshot{
		Revision:           1,
		NodeAccessEnforced: true,
		Users:              []cluster.SnapshotUser{{ID: 7, Username: "alice", Role: "user", Status: "active"}},
		Tokens:             []cluster.SnapshotToken{{ID: 9, UserID: 7, Name: "desktop", TokenHash: security.TokenHash("ak_secret"), Status: "active", MaxProxyCount: 1}},
	}
	payload, _ := json.Marshal(snapshot)
	if err := state.ApplyIdentitySnapshot(ctx, payload); err != nil {
		t.Fatal(err)
	}
	_, _, client, err := state.Credential(ctx, security.TokenHash("ak_secret"), "hwid-test", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.EnqueueClientCommand(ctx, 9, "hwid-test", "show_warning", "hello"); err != nil {
		t.Fatal(err)
	}
	commands, err := state.PopClientCommands(ctx, client.ID)
	if err != nil || len(commands) != 1 {
		t.Fatalf("queued command=%#v err=%v", commands, err)
	}
	commandID := commands[0]["id"].(int64)
	server := NewServer(config.Config{Mode: config.ModeEdge, ConfigState: "configured"}, nil, WithEdgeRuntime(state, nil))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/client/commands/"+strconv.FormatInt(commandID, 10)+"/ack", strings.NewReader(`{"access_token":"ak_secret","client_id":"hwid-test"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"ok":true`) {
		t.Fatalf("ACK failed: %d %s", recorder.Code, recorder.Body.String())
	}
	commands, err = state.PopClientCommands(ctx, client.ID)
	if err != nil || len(commands) != 0 {
		t.Fatalf("ACKed command was retried: %#v err=%v", commands, err)
	}
}

func TestEdgeClientLogoutImmediatelyRevokesRuntimeLease(t *testing.T) {
	ctx := context.Background()
	state, err := edgestate.Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	snapshot := cluster.IdentitySnapshot{
		Revision:           1,
		NodeAccessEnforced: true,
		Users:              []cluster.SnapshotUser{{ID: 7, Username: "alice", Role: "user", Status: "active"}},
		Tokens:             []cluster.SnapshotToken{{ID: 9, UserID: 7, Name: "desktop", TokenHash: security.TokenHash("ak_secret"), Status: "active", MaxProxyCount: 1}},
	}
	payload, _ := json.Marshal(snapshot)
	if err := state.ApplyIdentitySnapshot(ctx, payload); err != nil {
		t.Fatal(err)
	}
	_, _, client, err := state.Credential(ctx, security.TokenHash("ak_secret"), "hwid-test", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.TouchClient(ctx, client.ID, true); err != nil {
		t.Fatal(err)
	}
	lease := db.RuntimeLease{LeaseID: "lease-test", UserID: 7, TokenID: 9, ClientID: "hwid-test", RuntimeTokenHash: security.TokenHash("rt_secret"), Status: "active", ExpiresAt: time.Now().Add(24 * time.Hour)}
	if err := state.CreateLease(ctx, lease, nil); err != nil {
		t.Fatal(err)
	}
	server := NewServer(config.Config{Mode: config.ModeEdge, ConfigState: "configured"}, nil, WithEdgeRuntime(state, nil))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/client/logout", strings.NewReader(`{"access_token":"ak_secret","client_id":"hwid-test","frpc_running":true}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Routes().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"logged_out"`) {
		t.Fatalf("logout failed: %d %s", recorder.Code, recorder.Body.String())
	}
	stored, err := state.RuntimeLease(ctx, security.TokenHash("rt_secret"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "revoked" {
		t.Fatalf("logout must revoke runtime lease immediately: %#v", stored)
	}
	if state.ClientFresh(ctx, client.ID, 60) {
		t.Fatal("logout must clear client presence immediately")
	}
}

func TestEdgeHeartbeatTimeoutRevokesRuntimeLease(t *testing.T) {
	ctx := context.Background()
	state, err := edgestate.Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	snapshot := cluster.IdentitySnapshot{
		Revision:           1,
		NodeAccessEnforced: true,
		Users:              []cluster.SnapshotUser{{ID: 7, Username: "alice", Role: "user", Status: "active"}},
		Tokens:             []cluster.SnapshotToken{{ID: 9, UserID: 7, Name: "desktop", TokenHash: security.TokenHash("ak_secret"), Status: "active", MaxProxyCount: 1}},
	}
	payload, _ := json.Marshal(snapshot)
	if err := state.ApplyIdentitySnapshot(ctx, payload); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := state.Credential(ctx, security.TokenHash("ak_secret"), "hwid-test", true); err != nil {
		t.Fatal(err)
	}
	lease := db.RuntimeLease{LeaseID: "lease-timeout", UserID: 7, TokenID: 9, ClientID: "hwid-test", RuntimeTokenHash: security.TokenHash("rt_timeout"), Status: "active", ExpiresAt: time.Now().Add(24 * time.Hour)}
	if err := state.CreateLease(ctx, lease, nil); err != nil {
		t.Fatal(err)
	}
	server := newConnectedTestEdge(t, state)
	if err := server.enforceClientHeartbeatTimeout(ctx); err != nil {
		t.Fatal(err)
	}
	stored, err := state.RuntimeLease(ctx, security.TokenHash("rt_timeout"))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "revoked" {
		t.Fatalf("heartbeat timeout must revoke runtime lease: %#v", stored)
	}
}
