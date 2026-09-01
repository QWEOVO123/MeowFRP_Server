package cluster

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type PKIPaths struct {
	CAFile    string
	CAKeyFile string
	CertFile  string
	KeyFile   string
}

type PKIMaterial struct {
	CACertificate []byte
	CAPrivateKey  []byte
	Certificate   []byte
	PrivateKey    []byte
}

func LoadPKIMaterial(paths PKIPaths) (PKIMaterial, error) {
	var material PKIMaterial
	files := []struct {
		path   string
		target *[]byte
	}{{paths.CAFile, &material.CACertificate}, {paths.CAKeyFile, &material.CAPrivateKey}, {paths.CertFile, &material.Certificate}, {paths.KeyFile, &material.PrivateKey}}
	for _, file := range files {
		data, err := os.ReadFile(file.path)
		if err != nil {
			return PKIMaterial{}, err
		}
		*file.target = data
	}
	return material, nil
}

func GenerateControllerPKI(publicAddress string) (PKIMaterial, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return PKIMaterial{}, err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{SerialNumber: randomSerial(), Subject: pkix.Name{CommonName: "MeowFRP Node CA"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return PKIMaterial{}, err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return PKIMaterial{}, err
	}
	serverTemplate := &x509.Certificate{SerialNumber: randomSerial(), Subject: pkix.Name{CommonName: "MeowFRP Controller"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(2, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	host := publicAddress
	if parsed, _, splitErr := net.SplitHostPort(publicAddress); splitErr == nil {
		host = parsed
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, ip)
	} else if host != "" {
		serverTemplate.DNSNames = append(serverTemplate.DNSNames, host)
	}
	serverTemplate.DNSNames = appendUnique(serverTemplate.DNSNames, "localhost")
	serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, net.ParseIP("127.0.0.1"))
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return PKIMaterial{}, err
	}
	return PKIMaterial{CACertificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), CAPrivateKey: pem.EncodeToMemory(pemForECKey(caKey)), Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), PrivateKey: pem.EncodeToMemory(pemForECKey(serverKey))}, nil
}

func SignNodeCSRMaterial(material PKIMaterial, nodeID string, csrPEM []byte) ([]byte, string, time.Time, error) {
	certBlock, _ := pem.Decode(material.CACertificate)
	keyBlock, _ := pem.Decode(material.CAPrivateKey)
	if certBlock == nil || keyBlock == nil {
		return nil, "", time.Time{}, errors.New("invalid controller CA material")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, "", time.Time{}, errors.New("invalid certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, "", time.Time{}, errors.New("invalid certificate request signature")
	}
	now := time.Now()
	serial := randomSerial()
	expires := now.AddDate(1, 0, 0)
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: nodeID, Organization: []string{"MeowFRP Edge Nodes"}}, NotBefore: now.Add(-5 * time.Minute), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, DNSNames: []string{nodeID}}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), serial.Text(16), expires, nil
}

func ControllerCertificateCovers(material PKIMaterial, publicAddress string) error {
	if _, err := tls.X509KeyPair(material.Certificate, material.PrivateKey); err != nil {
		return err
	}
	block, _ := pem.Decode(material.Certificate)
	if block == nil {
		return errors.New("invalid controller certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	host := publicAddress
	if parsed, _, splitErr := net.SplitHostPort(publicAddress); splitErr == nil {
		host = parsed
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return errors.New("empty controller public address")
	}
	return cert.VerifyHostname(host)
}

func ReissueControllerServerCertificate(material PKIMaterial, publicAddress string) (PKIMaterial, error) {
	certBlock, _ := pem.Decode(material.CACertificate)
	keyBlock, _ := pem.Decode(material.CAPrivateKey)
	if certBlock == nil || keyBlock == nil {
		return material, errors.New("invalid controller CA material")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return material, err
	}
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return material, err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return material, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: randomSerial(), Subject: pkix.Name{CommonName: "MeowFRP Controller"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(2, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	host := publicAddress
	if parsed, _, splitErr := net.SplitHostPort(publicAddress); splitErr == nil {
		host = parsed
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else if host != "" {
		template.DNSNames = append(template.DNSNames, host)
	}
	template.DNSNames = appendUnique(template.DNSNames, "localhost")
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return material, err
	}
	material.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	material.PrivateKey = pem.EncodeToMemory(pemForECKey(serverKey))
	return material, nil
}

func DefaultPKIPaths(configPath string) PKIPaths {
	dir := filepath.Join(filepath.Dir(configPath), "data", "cluster-pki")
	return PKIPaths{
		CAFile: filepath.Join(dir, "node-ca.crt"), CAKeyFile: filepath.Join(dir, "node-ca.key"),
		CertFile: filepath.Join(dir, "controller.crt"), KeyFile: filepath.Join(dir, "controller.key"),
	}
}

func EnsureControllerPKI(paths PKIPaths, publicAddress string) error {
	if allExist(paths.CAFile, paths.CAKeyFile, paths.CertFile, paths.KeyFile) {
		certPEM, err := os.ReadFile(paths.CertFile)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return errors.New("invalid controller certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		host := publicAddress
		if parsedHost, _, splitErr := net.SplitHostPort(publicAddress); splitErr == nil {
			host = parsedHost
		}
		host = strings.Trim(host, "[]")
		if host != "" {
			if err := cert.VerifyHostname(host); err != nil {
				return fmt.Errorf("controller certificate does not cover public address %q: %w", host, err)
			}
		}
		return nil
	}
	if anyExist(paths.CAFile, paths.CAKeyFile, paths.CertFile, paths.KeyFile) {
		return errors.New("controller PKI is incomplete; restore the missing file instead of rotating node identity")
	}
	if err := os.MkdirAll(filepath.Dir(paths.CAFile), 0o700); err != nil {
		return err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: randomSerial(), Subject: pkix.Name{CommonName: "MeowFRP Node CA"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: randomSerial(), Subject: pkix.Name{CommonName: "MeowFRP Controller"},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(2, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	host := publicAddress
	if parsedHost, _, err := net.SplitHostPort(publicAddress); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	if ip := net.ParseIP(host); ip != nil {
		serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, ip)
	} else if host != "" {
		serverTemplate.DNSNames = append(serverTemplate.DNSNames, host)
	}
	serverTemplate.DNSNames = appendUnique(serverTemplate.DNSNames, "localhost")
	serverTemplate.IPAddresses = append(serverTemplate.IPAddresses, net.ParseIP("127.0.0.1"))
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	files := []struct {
		path  string
		block *pem.Block
	}{
		{paths.CAFile, &pem.Block{Type: "CERTIFICATE", Bytes: caDER}},
		{paths.CAKeyFile, pemForECKey(caKey)},
		{paths.CertFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverDER}},
		{paths.KeyFile, pemForECKey(serverKey)},
	}
	for _, file := range files {
		if err := os.WriteFile(file.path, pem.EncodeToMemory(file.block), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func SignNodeCSR(paths PKIPaths, nodeID string, csrPEM []byte) ([]byte, string, time.Time, error) {
	caCert, caKey, err := loadCA(paths.CAFile, paths.CAKeyFile)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, "", time.Time{}, errors.New("invalid certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, "", time.Time{}, errors.New("invalid certificate request signature")
	}
	now := time.Now()
	serial := randomSerial()
	expires := now.AddDate(1, 0, 0)
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: nodeID, Organization: []string{"MeowFRP Edge Nodes"}},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: expires,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames: []string{nodeID},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), serial.Text(16), expires, nil
}

func NewNodeKeyAndCSR(nodeName string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: nodeName}}, key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(pemForECKey(key)), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func CertificateFingerprint(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("invalid certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || keyBlock == nil {
		return nil, nil, errors.New("invalid controller CA files")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func pemForECKey(key *ecdsa.PrivateKey) *pem.Block {
	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic(fmt.Sprintf("marshal EC key: %v", err))
	}
	return &pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}
}

func randomSerial() *big.Int {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return serial
}

func allExist(paths ...string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

func anyExist(paths ...string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func appendUnique(values []string, value string) []string {
	for _, current := range values {
		if current == value {
			return values
		}
	}
	return append(values, value)
}
