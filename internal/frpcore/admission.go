package frpcore

import (
	"fmt"
	"frp-control-server/internal/db"
	"github.com/fatedier/frp/pkg/plugin/server"
	frpserver "github.com/fatedier/frp/server"
)

func clientKey(tokenID int64, clientID string) string { return fmt.Sprintf("%d:%s", tokenID, clientID) }

// The write lock waits for in-flight registrations to finish before we start
// draining; therefore zero cannot race with a successful new registration.
func (m *Manager) SetAdmissionClosed(closed bool) {
	m.admissionMu.Lock()
	defer m.admissionMu.Unlock()
	m.admissionClosed = closed
	if closed {
		m.mu.Lock()
		for _, lease := range m.runtimeLeases {
			m.drainingClients[clientKey(lease.TokenID, lease.ClientID)] = true
		}
		m.mu.Unlock()
	}
}

// A short database interruption pauses allocation but is not yet a terminal
// fault. Do not make previously authenticated clients drain before 10 seconds.
func (m *Manager) PauseAdmission() {
	m.admissionMu.Lock()
	m.admissionClosed = true
	m.admissionMu.Unlock()
}

func (m *Manager) RememberRuntimeLease(lease db.RuntimeLease) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runtimeLeases[lease.LeaseID] = lease
}

func (m *Manager) ClientDraining(tokenID int64, clientID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.drainingClients[clientKey(tokenID, clientID)]
}

func (m *Manager) FinishClientDrain(tokenID int64, clientID string) {
	m.admissionMu.Lock()
	defer m.admissionMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	key := clientKey(tokenID, clientID)
	if m.proxyCounts[key] > 0 {
		return
	}
	delete(m.drainingClients, key)
	for id, l := range m.runtimeLeases {
		if clientKey(l.TokenID, l.ClientID) == key {
			delete(m.runtimeLeases, id)
		}
	}
}

func (m *Manager) ClientProxyCount(tokenID int64, clientID string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.proxyCounts[clientKey(tokenID, clientID)]
}

// Only previously authenticated operational leases can keep forwarding.
// This map cannot authenticate a new user or allocate any new port.
func (m *Manager) ExistingRuntime(leaseID, hash string) (db.RuntimeLease, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	l, ok := m.runtimeLeases[leaseID]
	return l, ok && l.Status == "active" && l.RuntimeTokenHash == hash
}

func (m *Manager) proxyLifecycle() *frpserver.ProxyLifecycle {
	return &frpserver.ProxyLifecycle{
		Begin: func(user server.UserInfo) (func(), error) {
			m.admissionMu.RLock()
			m.mu.RLock()
			lease, known := m.runtimeLeases[user.Metas["lease_id"]]
			draining := m.drainingClients[clientKey(lease.TokenID, lease.ClientID)]
			m.mu.RUnlock()
			if m.admissionClosed || !known || lease.Status != "active" || draining {
				m.admissionMu.RUnlock()
				return nil, fmt.Errorf("节点异常：禁止开启新穿透端口")
			}
			return m.admissionMu.RUnlock, nil
		},
		Opened: func(user server.UserInfo, name string) {
			m.mu.Lock()
			key := user.RunID + "\x00" + name
			if old, ok := m.registeredProxies[key]; ok {
				m.removeProxyCountLocked(old)
			}
			id := user.Metas["lease_id"]
			m.registeredProxies[key] = id
			lease := m.runtimeLeases[id]
			m.proxyCounts[clientKey(lease.TokenID, lease.ClientID)]++
			m.leaseProxyCounts[id]++
			m.mu.Unlock()
		},
		Closed: func(user server.UserInfo, name string) {
			m.mu.Lock()
			key := user.RunID + "\x00" + name
			if id, ok := m.registeredProxies[key]; ok {
				m.removeProxyCountLocked(id)
				delete(m.registeredProxies, key)
			}
			m.mu.Unlock()
		},
	}
}

func (m *Manager) removeProxyCountLocked(id string) {
	lease := m.runtimeLeases[id]
	key := clientKey(lease.TokenID, lease.ClientID)
	if m.proxyCounts[key] <= 1 {
		delete(m.proxyCounts, key)
	} else {
		m.proxyCounts[key]--
	}
	if m.leaseProxyCounts[id] <= 1 {
		delete(m.leaseProxyCounts, id)
	} else {
		m.leaseProxyCounts[id]--
	}
}

// An explicit ban/logout must not be revived by a later outage fallback.
func (m *Manager) invalidateRuntime(match func(db.RuntimeLease) bool) {
	m.admissionMu.Lock()
	defer m.admissionMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, lease := range m.runtimeLeases {
		if match(lease) {
			lease.Status = "revoked"
			m.runtimeLeases[id] = lease
		}
	}
}
