package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
	"frp-control-server/internal/edgestate"
	"frp-control-server/internal/security"
)

func testFaultServer(t *testing.T, embedded bool) *Server {
	t.Helper()
	s := NewServer(config.Config{Mode: config.ModeController, EmbeddedFRPEnabled: embedded}, nil)
	t.Cleanup(func() { _ = s.core.Close() })
	s.rememberClient("ak_test", &db.Client{ID: 1, TokenID: 9, ClientID: "desktop"}, true)
	s.core.RememberRuntimeLease(db.RuntimeLease{LeaseID: "lease", TokenID: 9, ClientID: "desktop", RuntimeTokenHash: "rt_hash", Status: "active"})
	return s
}

func TestControllerDatabaseFaultTenSecondBoundaryAndRecovery(t *testing.T) {
	s := testFaultServer(t, true)
	control := cluster.NewControllerServer(nil, cluster.PKIPaths{})
	s.controllerControl = control
	start := time.Now()
	var failedSince time.Time
	failure := errors.New("database offline")
	s.observeControllerDatabaseHealth(start, failure, &failedSince)
	if !s.nodeUnavailable() || !control.DatabaseUnavailable() || control.DatabaseFault() || s.clientIsDraining(9, "desktop") {
		t.Fatal("initial failure must pause, not drain")
	}
	recorder := httptest.NewRecorder()
	if !s.faultHeartbeat(recorder, httptest.NewRequest("POST", "/", nil), clientHeartbeatRequest{AccessToken: "ak_test", ClientID: "desktop"}) || !strings.Contains(recorder.Body.String(), `"status":"node_recovering"`) || strings.Contains(recorder.Body.String(), "reauth") {
		t.Fatalf("brief outage must not log out: %s", recorder.Body.String())
	}
	s.observeControllerDatabaseHealth(start.Add(10*time.Second-time.Nanosecond), failure, &failedSince)
	if control.DatabaseFault() || s.clientIsDraining(9, "desktop") {
		t.Fatal("fault declared before 10 seconds")
	}
	s.observeControllerDatabaseHealth(start.Add(10*time.Second), failure, &failedSince)
	if !control.DatabaseFault() || !s.clientIsDraining(9, "desktop") {
		t.Fatal("10-second failure did not drain clients")
	}
	s.observeControllerDatabaseHealth(start.Add(11*time.Second), nil, &failedSince)
	if s.nodeUnavailable() || control.DatabaseUnavailable() || control.DatabaseFault() || !failedSince.IsZero() {
		t.Fatal("recovery did not reopen admission")
	}
	if !s.clientIsDraining(9, "desktop") {
		t.Fatal("recovery must not silently revive a draining client")
	}
	s.rememberClient("ak_test", &db.Client{ID: 1, TokenID: 9, ClientID: "desktop"}, true)
	if s.clientIsDraining(9, "desktop") {
		t.Fatal("explicit relog after zero proxies did not clear drain")
	}
}

func TestBriefDatabaseRecoveryResetsFailureTimerWithoutLogout(t *testing.T) {
	s := testFaultServer(t, true)
	var failedSince time.Time
	start := time.Now()
	s.observeControllerDatabaseHealth(start, errors.New("brief"), &failedSince)
	s.observeControllerDatabaseHealth(start.Add(9*time.Second), nil, &failedSince)
	if s.nodeUnavailable() || s.clientIsDraining(9, "desktop") || !failedSince.IsZero() {
		t.Fatal("brief interruption became terminal")
	}
	s.observeControllerDatabaseHealth(start.Add(15*time.Second), errors.New("new outage"), &failedSince)
	if s.fault.databaseFailed || s.clientIsDraining(9, "desktop") {
		t.Fatal("new outage reused old timer")
	}
}

func TestFaultHeartbeatOnlyLogsOutKnownZeroProxyClients(t *testing.T) {
	for _, embedded := range []bool{true, false} {
		t.Run(map[bool]string{true: "authoritative", false: "external-frps"}[embedded], func(t *testing.T) {
			s := testFaultServer(t, embedded)
			s.transitionNodeFault(true)
			recorder := httptest.NewRecorder()
			s.faultHeartbeat(recorder, httptest.NewRequest("POST", "/", nil), clientHeartbeatRequest{AccessToken: "ak_test", ClientID: "desktop", FRPCRunning: true})
			var response struct {
				OK       bool `json:"ok"`
				Commands []struct {
					Command string `json:"command"`
				} `json:"commands"`
			}
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			want := "show_warning"
			if embedded {
				want = "reauth"
			}
			if !response.OK || len(response.Commands) != 1 || response.Commands[0].Command != want {
				t.Fatalf("response: %s", recorder.Body.String())
			}
			// A claimed running process is not proof of registered ports.
			unknown := httptest.NewRecorder()
			s.faultHeartbeat(unknown, httptest.NewRequest("POST", "/", nil), clientHeartbeatRequest{AccessToken: "wrong", ClientID: "desktop"})
			if unknown.Code != 503 {
				t.Fatalf("unknown token bypassed fault: %s", unknown.Body.String())
			}
		})
	}
}

func TestNodeFaultGuardsAllNewAuthenticationAndAllocationRoutes(t *testing.T) {
	s := testFaultServer(t, true)
	s.transitionNodeFault(true)
	for _, path := range []string{"/api/v1/client/login", "/api/v1/client/resource-policy", "/api/v1/client/bootstrap"} {
		recorder := httptest.NewRecorder()
		s.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
		if recorder.Code != 503 || !strings.Contains(recorder.Body.String(), "node_fault") {
			t.Fatalf("%s: %d %s", path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestFaultKeepsExistingFRPWorkButRefusesLoginAndNewProxy(t *testing.T) {
	s := testFaultServer(t, true)
	s.transitionNodeFault(true)
	s.core.RememberRuntimeLease(db.RuntimeLease{LeaseID: "known", TokenID: 9, ClientID: "desktop", RuntimeTokenHash: security.TokenHash("rt_test"), Status: "active"})
	for _, op := range []string{"Login", "NewProxy", "Ping", "NewWorkConn", "NewUserConn"} {
		recorder := httptest.NewRecorder()
		content := json.RawMessage(`{"user":{"metas":{"lease_id":"known","token":"rt_test"}}}`)
		if !s.faultFRPPlugin(recorder, frpPluginRequest{Op: op, Content: content}) {
			t.Fatalf("op %s not handled", op)
		}
		var response struct {
			Reject bool `json:"reject"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Reject != (op == "Login" || op == "NewProxy") {
			t.Fatalf("op %s: %s", op, recorder.Body.String())
		}
	}
	s.core.TerminateConnectionsForLease("known")
	if s.allowFaultRuntime(map[string]string{"lease_id": "known", "token": "rt_test"}) {
		t.Fatal("revoked runtime revived by outage fallback")
	}
}

func TestEdgeHeartbeatTimeoutPreservesLeaseWhileControllerUnavailable(t *testing.T) {
	state, err := edgestate.Open(filepath.Join(t.TempDir(), "edge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	ctx := context.Background()
	payload, _ := json.Marshal(cluster.IdentitySnapshot{Revision: 1, NodeAccessEnforced: true, Users: []cluster.SnapshotUser{{ID: 7, Username: "alice", Role: "user", Status: "active"}}, Tokens: []cluster.SnapshotToken{{ID: 9, UserID: 7, TokenHash: "ak_hash", Status: "active"}}})
	if err := state.ApplyIdentitySnapshot(ctx, payload); err != nil {
		t.Fatal(err)
	}
	lease := db.RuntimeLease{LeaseID: "fault-lease", TokenID: 9, ClientID: "desktop", RuntimeTokenHash: "rt_hash", Status: "active", ExpiresAt: time.Now().Add(time.Hour)}
	if err := state.CreateLease(ctx, lease, nil); err != nil {
		t.Fatal(err)
	}
	s := NewServer(config.Config{Mode: config.ModeEdge}, nil, WithEdgeRuntime(state, nil))
	t.Cleanup(func() { _ = s.core.Close() })
	if err := s.enforceClientHeartbeatTimeout(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := state.RuntimeLease(ctx, "rt_hash")
	if err != nil || got.Status != "active" {
		t.Fatalf("fault revoked lease: %#v %v", got, err)
	}
	// Local data failure may not be reopened by an unrelated control callback.
	s.fault.localFailed = true
	s.transitionNodeFault(true)
	s.transitionNodeFault(false)
	if !s.fault.closed {
		t.Fatal("control recovery reopened locally failed edge")
	}
}
