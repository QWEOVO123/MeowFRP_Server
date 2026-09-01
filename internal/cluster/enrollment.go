package cluster

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type enrollmentCode struct {
	Secret      string `json:"secret"`
	Fingerprint string `json:"fingerprint"`
}
type EnrollmentRequest struct {
	NodeName string `json:"node_name"`
	NodeID   string `json:"node_id,omitempty"`
	CSR      string `json:"csr"`
}
type EnrollmentResponse struct {
	NodeID         string    `json:"node_id"`
	Certificate    string    `json:"certificate"`
	CACertificate  string    `json:"ca_certificate"`
	ExpiresAt      time.Time `json:"expires_at"`
	MTLSAddress    string    `json:"mtls_address"`
	MTLSServerName string    `json:"mtls_server_name"`
}

func EncodeEnrollmentCode(secret, fingerprint string) string {
	data, _ := json.Marshal(enrollmentCode{Secret: secret, Fingerprint: fingerprint})
	return "menr_" + base64.RawURLEncoding.EncodeToString(data)
}

func DecodeEnrollmentCode(value string) (secret, fingerprint string, err error) {
	if !strings.HasPrefix(value, "menr_") {
		return "", "", errors.New("invalid enrollment token")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "menr_"))
	if err != nil {
		return "", "", errors.New("invalid enrollment token")
	}
	var code enrollmentCode
	if json.Unmarshal(data, &code) != nil || code.Secret == "" || len(code.Fingerprint) != 64 {
		return "", "", errors.New("invalid enrollment token")
	}
	return code.Secret, strings.ToLower(code.Fingerprint), nil
}

func EnrollEdge(ctx context.Context, address, nodeName, code string) (EnrollmentResponse, []byte, error) {
	return EnrollEdgeAs(ctx, address, nodeName, code, "")
}

func EnrollEdgeAs(ctx context.Context, address, nodeName, code, nodeID string) (EnrollmentResponse, []byte, error) {
	secret := strings.TrimSpace(code)
	fingerprint := ""
	if strings.HasPrefix(secret, "menr_") {
		var err error
		secret, fingerprint, err = DecodeEnrollmentCode(secret)
		if err != nil {
			return EnrollmentResponse{}, nil, err
		}
	}
	privateKey, csr, err := NewNodeKeyAndCSR(nodeName)
	if err != nil {
		return EnrollmentResponse{}, nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if fingerprint != "" {
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("controller did not present a certificate")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].Raw)
			if hex.EncodeToString(sum[:]) != fingerprint {
				return errors.New("controller certificate fingerprint mismatch")
			}
			return nil
		}
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 15 * time.Second}
	body, _ := json.Marshal(EnrollmentRequest{NodeName: nodeName, NodeID: strings.TrimSpace(nodeID), CSR: string(csr)})
	base := strings.TrimRight(strings.TrimSpace(address), "/")
	if !strings.Contains(base, "://") {
		base = "https://" + base
	}
	enrollURL := base + "/v1/nodes/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL, strings.NewReader(string(body)))
	if err != nil {
		return EnrollmentResponse{}, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := client.Do(req)
	if err != nil {
		return EnrollmentResponse{}, nil, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated {
		return EnrollmentResponse{}, nil, fmt.Errorf("controller enrollment failed: %s", strings.TrimSpace(string(data)))
	}
	var result EnrollmentResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return EnrollmentResponse{}, nil, err
	}
	if err := ValidateEnrollmentResult(result, privateKey); err != nil {
		return EnrollmentResponse{}, nil, fmt.Errorf("invalid enrollment response: %w", err)
	}
	return result, privateKey, nil
}

func ValidateEnrollmentResult(result EnrollmentResponse, privateKey []byte) error {
	if result.NodeID == "" || result.MTLSAddress == "" || result.MTLSServerName == "" {
		return errors.New("missing node or mTLS endpoint")
	}
	pair, err := tls.X509KeyPair([]byte(result.Certificate), privateKey)
	if err != nil {
		return errors.New("node certificate does not match generated private key")
	}
	if len(pair.Certificate) == 0 {
		return errors.New("empty node certificate")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if cert.Subject.CommonName != result.NodeID {
		return errors.New("node certificate identity mismatch")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(result.CACertificate)) {
		return errors.New("invalid controller CA certificate")
	}
	if _, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return err
	}
	return nil
}

func SaveEnrollment(configPath string, result EnrollmentResponse, privateKey []byte) (TLSFiles, error) {
	dir := filepath.Join(filepath.Dir(configPath), "data", "edge-pki")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return TLSFiles{}, err
	}
	paths := TLSFiles{CAFile: filepath.Join(dir, "controller-ca.crt"), CertFile: filepath.Join(dir, "node.crt"), KeyFile: filepath.Join(dir, "node.key")}
	for path, data := range map[string][]byte{paths.CAFile: []byte(result.CACertificate), paths.CertFile: []byte(result.Certificate), paths.KeyFile: privateKey} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return TLSFiles{}, err
		}
	}
	return paths, nil
}

type TLSFiles struct {
	CAFile   string
	CertFile string
	KeyFile  string
	CAPEM    []byte
	CertPEM  []byte
	KeyPEM   []byte
}

func ParseCSRPublicKey(csrPEM string) error {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return err
	}
	return csr.CheckSignature()
}
