// Package frptls owns node-local FRP identities. It never modifies OS trust stores.
package frptls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type persisted struct {
	Version          int    `json:"version"`
	Generation       string `json:"generation"`
	ServerName       string `json:"server_name"`
	CAPEM            string `json:"ca_pem"`
	CAKeyPEM         string `json:"ca_private_key_pem"`
	CertPEM          string `json:"certificate_pem"`
	KeyPEM           string `json:"private_key_pem"`
	LastResetCommand string `json:"last_reset_command,omitempty"`
}

type Public struct {
	Generation  string    `json:"generation"`
	ServerName  string    `json:"server_name"`
	CAPEM       string    `json:"ca_pem,omitempty"`
	Fingerprint string    `json:"ca_fingerprint"`
	NotAfter    time.Time `json:"expires_at"`
}

type Identity struct {
	mu          sync.RWMutex
	path        string
	state       persisted
	certificate tls.Certificate
	public      Public
}

func Open(path string) (*Identity, error) {
	i := &Identity{path: path}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		state, generateErr := generate("")
		if generateErr != nil {
			return nil, generateErr
		}
		if err = i.install(state, true); err != nil {
			return nil, err
		}
		return i, nil
	}
	if err != nil {
		return nil, err
	}
	var state persisted
	if err = json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("invalid FRP TLS identity file")
	}
	if err = i.install(state, false); err != nil {
		return nil, err
	}
	if err = i.EnsureFresh(); err != nil {
		return nil, err
	}
	return i, nil
}

func (i *Identity) Public(includeCA bool) Public {
	i.mu.RLock()
	defer i.mu.RUnlock()
	p := i.public
	if !includeCA {
		p.CAPEM = ""
	}
	return p
}

// Every handshake selects the current certificate. Rotation does not stop listeners.
func (i *Identity) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			i.mu.Lock()
			defer i.mu.Unlock()
			if err := i.refreshLocked(); err != nil {
				return nil, err
			}
			cert := i.certificate
			return &cert, nil
		}}
}

// Renewal keeps the root/name stable while replacing the leaf key. If the root
// itself is approaching expiry, the HTTPS API publishes a fresh identity first.
func (i *Identity) EnsureFresh() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.refreshLocked()
}

func (i *Identity) refreshLocked() error {
	if time.Until(i.public.NotAfter) > 30*24*time.Hour {
		return nil
	}
	block, _ := pem.Decode([]byte(i.state.CAPEM))
	if block == nil {
		return fmt.Errorf("invalid FRP root")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if time.Until(ca.NotAfter) <= 366*24*time.Hour {
		state, err := generate(i.state.LastResetCommand)
		if err != nil {
			return err
		}
		return i.install(state, true)
	}
	keyBlock, _ := pem.Decode([]byte(i.state.CAKeyPEM))
	if keyBlock == nil {
		return fmt.Errorf("invalid FRP CA key")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	caKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("unsupported FRP CA key")
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	number, err := serial()
	if err != nil {
		return err
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: number, Subject: pkix.Name{CommonName: i.state.ServerName}, DNSNames: []string{i.state.ServerName}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return err
	}
	state := i.state
	state.CertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	state.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return i.install(state, true)
}

// A durable command ID makes retries after process failure harmless.
func (i *Identity) Reset(commandID string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if commandID != "" && i.state.LastResetCommand == commandID {
		return nil
	}
	state, err := generate(commandID)
	if err != nil {
		return err
	}
	return i.install(state, true)
}

func (i *Identity) install(state persisted, save bool) error {
	if state.Version != 1 || state.Generation == "" || state.ServerName == "" {
		return fmt.Errorf("invalid FRP TLS identity metadata")
	}
	caBlock, _ := pem.Decode([]byte(state.CAPEM))
	if caBlock == nil {
		return fmt.Errorf("invalid FRP root certificate")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !ca.IsCA {
		return fmt.Errorf("invalid FRP root CA")
	}
	if err = ca.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("FRP root is not self-signed")
	}
	if _, err = tls.X509KeyPair([]byte(state.CAPEM), []byte(state.CAKeyPEM)); err != nil {
		return fmt.Errorf("FRP CA key does not match certificate")
	}
	cert, err := tls.X509KeyPair([]byte(state.CertPEM), []byte(state.KeyPEM))
	if err != nil {
		return fmt.Errorf("FRP server key does not match certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("invalid FRP server certificate")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	verifyTime := time.Now()
	if !save {
		// Validate the persisted chain cryptographically before renewing expired
		// material; never bypass hostname/signature/key checks or trust new roots.
		verifyTime = leaf.NotBefore
		if ca.NotBefore.After(verifyTime) {
			verifyTime = ca.NotBefore
		}
		verifyTime = verifyTime.Add(time.Second)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: state.ServerName, CurrentTime: verifyTime}); err != nil {
		return fmt.Errorf("FRP identity verification failed: %w", err)
	}
	cert.Leaf = leaf
	if save {
		data, marshalErr := json.MarshalIndent(state, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		if err = os.MkdirAll(filepath.Dir(i.path), 0700); err != nil {
			return err
		}
		file, createErr := os.CreateTemp(filepath.Dir(i.path), filepath.Base(i.path)+".tmp-*")
		if createErr != nil {
			return createErr
		}
		name := file.Name()
		defer os.Remove(name)
		if err = file.Chmod(0600); err == nil {
			_, err = file.Write(data)
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if err = os.Rename(name, i.path); err != nil {
			return err
		}
	}
	fingerprint := sha256.Sum256(ca.Raw)
	i.state, i.certificate = state, cert
	i.public = Public{Generation: state.Generation, ServerName: state.ServerName, CAPEM: state.CAPEM, Fingerprint: hex.EncodeToString(fingerprint[:]), NotAfter: leaf.NotAfter}
	return nil
}

func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }

func generate(commandID string) (persisted, error) {
	var s persisted
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return s, err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return s, err
	}
	id := make([]byte, 16)
	if _, err = rand.Read(id); err != nil {
		return s, err
	}
	s.Version, s.Generation, s.LastResetCommand = 1, hex.EncodeToString(id), commandID
	s.ServerName = "frp-" + s.Generation + ".internal"
	caSerial, err := serial()
	if err != nil {
		return s, err
	}
	serverSerial, err := serial()
	if err != nil {
		return s, err
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "MeowFRP FRP CA " + s.Generation}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, root, root, &caKey.PublicKey, caKey)
	if err != nil {
		return s, err
	}
	leaf := &x509.Certificate{SerialNumber: serverSerial, Subject: pkix.Name{CommonName: s.ServerName}, DNSNames: []string{s.ServerName}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &serverKey.PublicKey, caKey)
	if err != nil {
		return s, err
	}
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return s, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return s, err
	}
	s.CAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	s.CAKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER}))
	s.CertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	s.KeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return s, nil
}
