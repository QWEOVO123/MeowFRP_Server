package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultsUsePublicAPIAndTwentyFourHourRuntimeLease(t *testing.T) {
	t.Setenv("FRP_CONTROL_HTTP_ADDR", "")
	t.Setenv("FRP_CONTROL_RUNTIME_TOKEN_TTL", "")
	cfg := defaults()
	if cfg.HTTPAddr != ":8080" {
		t.Fatalf("expected all-interface API default, got %q", cfg.HTTPAddr)
	}
	if cfg.RuntimeTokenTTL != 24*time.Hour {
		t.Fatalf("expected 24 hour runtime lease, got %s", cfg.RuntimeTokenTTL)
	}
}

func TestWriteFileConfigCanReplaceExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	base := defaults()
	base.Mode = ModeController
	base.Initialized = true
	base.MySQLDSN = "user:pass@tcp(127.0.0.1:3306)/db"
	base.InitialAdmin = InitialAdminConfig{Username: "admin", PasswordHash: "hash"}
	if err := WriteFileConfig(path, base.FileConfig()); err != nil {
		t.Fatal(err)
	}
	base.ClientConfigComment = "updated"
	if err := WriteFileConfig(path, base.FileConfig()); err != nil {
		t.Fatal(err)
	}
	read, err := ReadFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if read.ClientConfigComment != "updated" {
		t.Fatalf("replacement did not persist: %q", read.ClientConfigComment)
	}
}

func TestLoadInvalidConfigEntersSetupState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FRP_CONTROL_CONFIG", path)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigState != "invalid" || cfg.Initialized {
		t.Fatalf("unexpected state: %#v", cfg)
	}
}

func TestLegacyConfigInfersControllerMode(t *testing.T) {
	cfg := defaults()
	applyFileConfig(&cfg, FileConfig{MySQLDSN: "dsn", Initialized: true, InitialAdmin: InitialAdminConfig{Username: "admin", PasswordHash: "hash"}})
	if cfg.Mode != ModeController {
		t.Fatalf("expected controller, got %q", cfg.Mode)
	}
}

func TestEmbeddedTLSMaterialRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	cfg := defaults()
	cfg.Mode = ModeEdge
	cfg.Initialized = true
	cfg.InitialAdmin = InitialAdminConfig{Username: "admin", PasswordHash: "hash"}
	cfg.Edge.NodeID = "node-test"
	cfg.Edge.ControllerAddr = "controller.example.test:9443"
	cfg.Edge.TLS = TLSFiles{CACertificateBase64: EncodePEM([]byte("ca")), CertificateBase64: EncodePEM([]byte("cert")), PrivateKeyBase64: EncodePEM([]byte("key"))}
	if err := WriteFileConfig(path, cfg.FileConfig()); err != nil {
		t.Fatal(err)
	}
	read, err := ReadFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded := defaults()
	applyFileConfig(&loaded, read)
	if stringMustDecode(t, loaded.Edge.TLS.PrivateKeyBase64) != "key" {
		t.Fatal("private key was not preserved")
	}
	if err := Validate(loaded); err != nil {
		t.Fatal(err)
	}
}

func TestNodeRuntimeRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.json")
	cfg := defaults()
	cfg.Mode = ModeController
	cfg.Initialized = true
	cfg.MySQLDSN = "dsn"
	cfg.InitialAdmin = InitialAdminConfig{Username: "admin", PasswordHash: "hash"}
	cfg.Node = NodeRuntimeConfig{Tag: "Shanghai", PublicAPIURL: "https://sh.example/api", FRPAdvertiseAddr: "sh.example", FRPBindPort: 7443, PortRangeStart: 20000, PortRangeEnd: 30000, Selectable: true}
	if err := WriteFileConfig(path, cfg.FileConfig()); err != nil {
		t.Fatal(err)
	}
	read, err := ReadFileConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded := defaults()
	applyFileConfig(&loaded, read)
	if loaded.Node != cfg.Node || loaded.FRPServerAddr != "sh.example" || loaded.FRPServerPort != 7443 {
		t.Fatalf("node runtime was not preserved: %#v", loaded.Node)
	}
}

func stringMustDecode(t *testing.T, value string) string {
	t.Helper()
	decoded, err := DecodePEM(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(decoded)
}
