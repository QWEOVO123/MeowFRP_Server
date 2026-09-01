package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrollmentUsesHTTPSAPIThenReturnsMTLSIdentity(t *testing.T) {
	material, err := GenerateControllerPKI("node.example.test:9443")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/nodes/enroll" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer enroll-secret" {
			http.Error(w, "bad token", 401)
			return
		}
		var request EnrollmentRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			http.Error(w, "bad json", 400)
			return
		}
		if request.NodeID != "node-existing" {
			t.Errorf("expected existing node identity, got %q", request.NodeID)
		}
		cert, _, expires, signErr := SignNodeCSRMaterial(material, request.NodeID, []byte(request.CSR))
		if signErr != nil {
			http.Error(w, signErr.Error(), 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(EnrollmentResponse{NodeID: request.NodeID, Certificate: string(cert), CACertificate: string(material.CACertificate), ExpiresAt: expires, MTLSAddress: "node.example.test:9443", MTLSServerName: "node.example.test"})
	}))
	defer server.Close()
	sum := sha256.Sum256(server.Certificate().Raw)
	code := EncodeEnrollmentCode("enroll-secret", hex.EncodeToString(sum[:]))
	result, key, err := EnrollEdgeAs(context.Background(), server.URL+"/api", "test edge", code, "node-existing")
	if err != nil {
		t.Fatal(err)
	}
	if result.NodeID != "node-existing" || len(key) == 0 {
		t.Fatalf("unexpected enrollment result: %#v", result)
	}
}
