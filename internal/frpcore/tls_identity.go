package frpcore

import (
	"fmt"
	"frp-control-server/internal/config"
	"frp-control-server/internal/frptls"
)

func (m *Manager) EnsureTLSIdentity(cfg config.Config) error {
	m.tlsInitMu.Lock()
	defer m.tlsInitMu.Unlock()
	m.mu.RLock()
	ready := m.tlsIdentity != nil
	m.mu.RUnlock()
	if ready {
		return nil
	}
	if cfg.ConfigPath == "" {
		return fmt.Errorf("FRP TLS requires a persistent node configuration path")
	}
	identity, err := frptls.Open(cfg.ConfigPath + ".frp-tls.json")
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.tlsIdentity = identity
	m.mu.Unlock()
	return nil
}

func (m *Manager) TLSPublic(includeCA bool) (frptls.Public, bool) {
	m.mu.RLock()
	identity := m.tlsIdentity
	m.mu.RUnlock()
	if identity == nil {
		return frptls.Public{}, false
	}
	if err := identity.EnsureFresh(); err != nil {
		return frptls.Public{}, false
	}
	return identity.Public(includeCA), true
}

func (m *Manager) ResetTLSIdentity(cfg config.Config, commandID string) error {
	if err := m.EnsureTLSIdentity(cfg); err != nil {
		return err
	}
	m.mu.RLock()
	identity := m.tlsIdentity
	m.mu.RUnlock()
	return identity.Reset(commandID)
}

func (m *Manager) SetTLSRequired(enabled bool) {
	m.mu.RLock()
	service := m.frps
	m.mu.RUnlock()
	if service != nil {
		service.SetTLSRequired(enabled)
	}
}

func (m *Manager) TLSRequired(cfg config.Config) bool {
	m.mu.RLock()
	service := m.frps
	m.mu.RUnlock()
	if service != nil {
		return service.TLSRequired()
	}
	return cfg.FRPTransportTLS
}
