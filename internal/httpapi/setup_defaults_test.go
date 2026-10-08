package httpapi

import (
	"net/http/httptest"
	"testing"

	"frp-control-server/internal/config"
)

func TestPublicIPv4RejectsNonPublicAddresses(t *testing.T) {
	for _, value := range []string{"127.0.0.1", "10.1.2.3", "100.64.0.1", "169.254.1.1", "172.16.1.1", "192.168.1.1", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "::1", "2001:db8::1", "<html>IP probe failed</html>"} {
		if _, ok := publicIPv4(value); ok {
			t.Fatalf("non-public IPv4 accepted: %s", value)
		}
	}
}

func TestPublicIPv4DecisionIsConservative(t *testing.T) {
	unique := decidePublicIPv4([]string{"1.1.1.1", "1.1.1.1"}, "interfaces", true)
	if unique.Address != "1.1.1.1" || unique.Status != "unique" || len(unique.Candidates) != 1 {
		t.Fatal("duplicate interface address is not a second IP")
	}
	multiple := decidePublicIPv4([]string{"1.1.1.1", "8.8.8.8"}, "egress", true)
	if multiple.Address != "127.0.0.1" || multiple.Status != "multiple" {
		t.Fatal("multiple public IPs must require manual selection")
	}
	partial := decidePublicIPv4([]string{"1.1.1.1"}, "egress", false)
	if partial.Address != "127.0.0.1" || partial.Status != "unavailable" {
		t.Fatal("one failed egress probe must not be treated as certain")
	}
	agree := decidePublicIPv4([]string{"1.1.1.1", "1.1.1.1"}, "egress", true)
	if agree.Address != "1.1.1.1" {
		t.Fatal("matching egress probes should suggest the public address")
	}
}

func TestControllerSetupDoesNotUseCDNHostAsFRPAddress(t *testing.T) {
	req := httptest.NewRequest("POST", "https://relay.qweovo.top/api/v1/system/setup-admin", nil)
	cfg := config.Config{Mode: config.ModeController, Node: config.NodeRuntimeConfig{FRPAdvertiseAddr: "127.0.0.1", PublicAPIURL: "https://manual.example/control/api"}}
	initializeNodeRuntimeFromRequest(&cfg, req, "中心节点")
	if cfg.Node.FRPAdvertiseAddr != "127.0.0.1" || cfg.Node.PublicAPIURL != "https://manual.example/control/api" {
		t.Fatal("explicit setup inputs must not be replaced by request defaults")
	}
}

func TestSetupDiscoveryNotAvailableAfterInitialization(t *testing.T) {
	s := NewServer(config.Config{Initialized: true}, nil)
	defer s.core.Close()
	response := httptest.NewRecorder()
	s.setupDefaults(response, httptest.NewRequest("GET", "/api/v1/system/setup-defaults", nil))
	if response.Code != 409 {
		t.Fatal("setup-only discovery should be unavailable after initialization")
	}
}

func TestFRPAddressCannotContainAPISchemeOrPort(t *testing.T) {
	for _, value := range []string{"https://relay.qweovo.top/api", "relay.qweovo.top:7000", "user@relay.qweovo.top", ""} {
		if validateFRPAdvertiseAddress(value) == nil {
			t.Fatalf("invalid FRP host accepted: %s", value)
		}
	}
	for _, value := range []string{"127.0.0.1", "1.1.1.1", "relay.qweovo.top", "::1"} {
		if err := validateFRPAdvertiseAddress(value); err != nil {
			t.Fatal(err)
		}
	}
}
