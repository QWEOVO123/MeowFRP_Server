package cluster

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEnrollmentCodeRoundTrip(t *testing.T) {
	fingerprint := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	secret, gotFingerprint, err := DecodeEnrollmentCode(EncodeEnrollmentCode("secret", fingerprint))
	if err != nil || secret != "secret" || gotFingerprint != fingerprint {
		t.Fatalf("unexpected enrollment code result: %q %q %v", secret, gotFingerprint, err)
	}
}

func TestControllerPKIAndNodeCertificate(t *testing.T) {
	dir := t.TempDir()
	paths := PKIPaths{CAFile: filepath.Join(dir, "ca.crt"), CAKeyFile: filepath.Join(dir, "ca.key"), CertFile: filepath.Join(dir, "server.crt"), KeyFile: filepath.Join(dir, "server.key")}
	if err := EnsureControllerPKI(paths, "controller.example.com:9443"); err != nil {
		t.Fatal(err)
	}
	privateKey, csr, err := NewNodeKeyAndCSR("edge-test")
	if err != nil || len(privateKey) == 0 {
		t.Fatal(err)
	}
	certPEM, serial, expires, err := SignNodeCSR(paths, "node_test", csr)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "node_test" || cert.SerialNumber.Text(16) != serial {
		t.Fatalf("unexpected node certificate: %#v", cert.Subject)
	}
	remaining := time.Until(expires)
	if remaining < 364*24*time.Hour || remaining > 366*24*time.Hour {
		t.Fatalf("expected one-year edge certificate, got %s", remaining)
	}
}

func TestControllerPKIRejectsPartialState(t *testing.T) {
	dir := t.TempDir()
	paths := PKIPaths{CAFile: filepath.Join(dir, "ca.crt"), CAKeyFile: filepath.Join(dir, "ca.key"), CertFile: filepath.Join(dir, "server.crt"), KeyFile: filepath.Join(dir, "server.key")}
	if err := os.WriteFile(paths.CAFile, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureControllerPKI(paths, "localhost:9443"); err == nil {
		t.Fatal("expected partial PKI error")
	}
}
