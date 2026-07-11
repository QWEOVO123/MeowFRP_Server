package frpcore

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/dpihook"
	frpserver "github.com/fatedier/frp/server"

	"frp-control-server/internal/dpi"
	"frp-control-server/internal/dpiengine"
)

const (
	defaultUDPFlowTimeout = 10 * time.Second
	udpCleanupInterval    = time.Second
	maxTrackedUDPFlows    = 32768
)

type Inspector interface {
	Inspect(context.Context, dpiengine.TrafficSample) dpi.Decision
}

type ProxyBinding struct {
	UserID     int64
	TokenID    int64
	ClientID   string
	ClientAddr string
	LeaseID    string
	ProxyName  string
	ProxyType  string
	RemotePort int
}

type ActiveConnection struct {
	ID           string    `json:"id"`
	Protocol     string    `json:"protocol"`
	UserID       int64     `json:"user_id"`
	TokenID      int64     `json:"token_id"`
	ClientID     string    `json:"client_id"`
	ClientAddr   string    `json:"client_addr"`
	LeaseID      string    `json:"lease_id"`
	ProxyName    string    `json:"proxy_name"`
	ProxyType    string    `json:"proxy_type"`
	RemotePort   int       `json:"remote_port"`
	InboundAddr  string    `json:"inbound_addr"`
	InboundIP    string    `json:"inbound_ip"`
	InboundPort  int       `json:"inbound_port"`
	ServerAddr   string    `json:"server_addr"`
	OpenedAt     time.Time `json:"opened_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	CanTerminate bool      `json:"can_terminate"`
}

type BlockedInboundIP struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

type activeTCPConnection struct {
	ActiveConnection
	userConn net.Conn
	workConn io.Closer
}

type Manager struct {
	mu                   sync.RWMutex
	closeOnce            sync.Once
	inspector            Inspector
	bindings             map[string]ProxyBinding
	leaseClientAddresses map[string]string
	tcpConnections       map[string]*activeTCPConnection
	udpFlows             map[string]ActiveConnection
	blockedInboundIPs    map[string]BlockedInboundIP
	nextConnectionID     uint64
	udpFlowTimeout       time.Duration
	maxUDPFlows          int
	cleanupStop          chan struct{}
	cleanupDone          chan struct{}
	frps                 *frpserver.Service
	running              bool
}

func NewManager(inspector Inspector) *Manager {
	manager := &Manager{
		inspector:            inspector,
		bindings:             map[string]ProxyBinding{},
		leaseClientAddresses: map[string]string{},
		tcpConnections:       map[string]*activeTCPConnection{},
		udpFlows:             map[string]ActiveConnection{},
		blockedInboundIPs:    map[string]BlockedInboundIP{},
		udpFlowTimeout:       defaultUDPFlowTimeout,
		maxUDPFlows:          maxTrackedUDPFlows,
		cleanupStop:          make(chan struct{}),
		cleanupDone:          make(chan struct{}),
	}
	go manager.runConnectionCleanup()
	return manager
}

func (m *Manager) SetUDPFlowTimeout(timeout time.Duration) {
	if timeout <= 0 {
		timeout = defaultUDPFlowTimeout
	}
	m.mu.Lock()
	m.udpFlowTimeout = timeout
	m.mu.Unlock()
}

func (m *Manager) SetInspector(inspector Inspector) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inspector = inspector
}

func (m *Manager) BindProxy(binding ProxyBinding) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if binding.ClientAddr == "" {
		binding.ClientAddr = m.leaseClientAddresses[binding.LeaseID]
	}
	m.bindings[bindingKey(binding.LeaseID, binding.ProxyName)] = binding
}

func (m *Manager) UnbindProxy(leaseID, proxyName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.bindings, bindingKey(leaseID, proxyName))
}

func (m *Manager) LookupProxy(leaseID, proxyName string) (ProxyBinding, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	binding, ok := m.bindings[bindingKey(leaseID, proxyName)]
	return binding, ok
}

func (m *Manager) SetLeaseClientAddress(leaseID, clientAddress string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	clientAddress = strings.TrimSpace(clientAddress)
	m.leaseClientAddresses[leaseID] = clientAddress
	for key, binding := range m.bindings {
		if binding.LeaseID == leaseID {
			binding.ClientAddr = clientAddress
			m.bindings[key] = binding
		}
	}
	for _, conn := range m.tcpConnections {
		if conn.LeaseID == leaseID {
			conn.ClientAddr = clientAddress
		}
	}
	for key, flow := range m.udpFlows {
		if flow.LeaseID == leaseID {
			flow.ClientAddr = clientAddress
			m.udpFlows[key] = flow
		}
	}
}

func (m *Manager) IsInboundBlocked(_ context.Context, info dpihook.ConnectionInfo) bool {
	ip, _ := splitAddr(info.RemoteAddr)
	if ip == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, blocked := m.blockedInboundIPs[ip]
	return blocked
}

func (m *Manager) RegisterTCPConnection(_ context.Context, info dpihook.ConnectionInfo, userConn net.Conn, workConn io.Closer) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextConnectionID++
	id := "tcp_" + strconv.FormatUint(m.nextConnectionID, 10)
	now := time.Now()
	binding := m.bindingForLocked(info.LeaseID, info.ProxyName)
	inboundIP, inboundPort := splitAddr(info.RemoteAddr)
	conn := &activeTCPConnection{
		ActiveConnection: ActiveConnection{
			ID:           id,
			Protocol:     "tcp",
			UserID:       binding.UserID,
			TokenID:      binding.TokenID,
			ClientID:     binding.ClientID,
			ClientAddr:   binding.ClientAddr,
			LeaseID:      info.LeaseID,
			ProxyName:    info.ProxyName,
			ProxyType:    valueOr(info.ProxyType, binding.ProxyType),
			RemotePort:   binding.RemotePort,
			InboundAddr:  info.RemoteAddr,
			InboundIP:    inboundIP,
			InboundPort:  inboundPort,
			ServerAddr:   info.LocalAddr,
			OpenedAt:     now,
			LastSeenAt:   now,
			CanTerminate: true,
		},
		userConn: userConn,
		workConn: workConn,
	}
	m.tcpConnections[id] = conn
	return id
}

func (m *Manager) UnregisterTCPConnection(id string) {
	if id == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tcpConnections, id)
}

func (m *Manager) ObserveUDPFlow(_ context.Context, info dpihook.ConnectionInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	binding := m.bindingForLocked(info.LeaseID, info.ProxyName)
	inboundIP, inboundPort := splitAddr(info.RemoteAddr)
	key := strings.Join([]string{info.LeaseID, info.ProxyName, info.RemoteAddr}, "\x00")
	flow := m.udpFlows[key]
	if flow.ID == "" {
		if m.maxUDPFlows > 0 && len(m.udpFlows) >= m.maxUDPFlows {
			return
		}
		m.nextConnectionID++
		flow.ID = "udp_" + strconv.FormatUint(m.nextConnectionID, 10)
		flow.OpenedAt = now
	}
	flow.Protocol = "udp"
	flow.UserID = binding.UserID
	flow.TokenID = binding.TokenID
	flow.ClientID = binding.ClientID
	flow.ClientAddr = binding.ClientAddr
	flow.LeaseID = info.LeaseID
	flow.ProxyName = info.ProxyName
	flow.ProxyType = valueOr(info.ProxyType, binding.ProxyType)
	flow.RemotePort = binding.RemotePort
	flow.InboundAddr = info.RemoteAddr
	flow.InboundIP = inboundIP
	flow.InboundPort = inboundPort
	flow.ServerAddr = info.LocalAddr
	flow.LastSeenAt = now
	flow.CanTerminate = false
	m.udpFlows[key] = flow
}

func (m *Manager) ListConnections(udpTimeout time.Duration) []ActiveConnection {
	if udpTimeout <= 0 {
		udpTimeout = defaultUDPFlowTimeout
	}
	now := time.Now()
	m.mu.RLock()
	defer m.mu.RUnlock()
	connections := make([]ActiveConnection, 0, len(m.tcpConnections)+len(m.udpFlows))
	for _, conn := range m.tcpConnections {
		connections = append(connections, conn.ActiveConnection)
	}
	for _, flow := range m.udpFlows {
		if now.Sub(flow.LastSeenAt) > udpTimeout {
			continue
		}
		connections = append(connections, flow)
	}
	return connections
}

func (m *Manager) TerminateTCPConnection(id string) bool {
	m.mu.Lock()
	conn := m.tcpConnections[id]
	delete(m.tcpConnections, id)
	m.mu.Unlock()
	if conn == nil {
		return false
	}
	abortiveClose(conn.userConn)
	if conn.workConn != nil {
		abortiveClose(conn.workConn)
	}
	return true
}

func (m *Manager) TerminateConnectionsForUser(userID int64) int {
	if userID <= 0 {
		return 0
	}
	return m.terminateConnections(func(conn ActiveConnection) bool {
		return conn.UserID == userID
	})
}

func (m *Manager) TerminateConnectionsForToken(tokenID int64) int {
	if tokenID <= 0 {
		return 0
	}
	return m.terminateConnections(func(conn ActiveConnection) bool {
		return conn.TokenID == tokenID
	})
}

func (m *Manager) TerminateConnectionsForClient(tokenID int64, clientID string) int {
	clientID = strings.TrimSpace(clientID)
	if tokenID <= 0 || clientID == "" {
		return 0
	}
	return m.terminateConnections(func(conn ActiveConnection) bool {
		return conn.TokenID == tokenID && conn.ClientID == clientID
	})
}

func (m *Manager) terminateConnections(match func(ActiveConnection) bool) int {
	m.mu.Lock()
	tcpToClose := make([]*activeTCPConnection, 0)
	closed := 0
	for key, conn := range m.tcpConnections {
		if match(conn.ActiveConnection) {
			tcpToClose = append(tcpToClose, conn)
			delete(m.tcpConnections, key)
			closed++
		}
	}
	for key, flow := range m.udpFlows {
		if match(flow) {
			delete(m.udpFlows, key)
			closed++
		}
	}
	m.mu.Unlock()
	for _, conn := range tcpToClose {
		abortiveClose(conn.userConn)
		if conn.workConn != nil {
			abortiveClose(conn.workConn)
		}
	}
	return closed
}

func (m *Manager) BlockInboundIP(ip, reason string) BlockedInboundIP {
	block := BlockedInboundIP{IP: strings.TrimSpace(ip), Reason: strings.TrimSpace(reason), CreatedAt: time.Now()}
	m.setBlockedInboundIP(block, true)
	return block
}

func (m *Manager) SetBlockedInboundIP(block BlockedInboundIP) {
	if block.CreatedAt.IsZero() {
		block.CreatedAt = time.Now()
	}
	m.setBlockedInboundIP(block, false)
}

func (m *Manager) setBlockedInboundIP(block BlockedInboundIP, closeExisting bool) {
	m.mu.Lock()
	m.blockedInboundIPs[block.IP] = block
	tcpToClose := make([]*activeTCPConnection, 0)
	if closeExisting {
		for key, conn := range m.tcpConnections {
			if conn.InboundIP == block.IP {
				tcpToClose = append(tcpToClose, conn)
				delete(m.tcpConnections, key)
			}
		}
	}
	for key, flow := range m.udpFlows {
		if flow.InboundIP == block.IP {
			delete(m.udpFlows, key)
		}
	}
	m.mu.Unlock()
	for _, conn := range tcpToClose {
		abortiveClose(conn.userConn)
		if conn.workConn != nil {
			abortiveClose(conn.workConn)
		}
	}
}

func (m *Manager) UnblockInboundIP(ip string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blockedInboundIPs, strings.TrimSpace(ip))
}

func (m *Manager) ListBlockedInboundIPs() []BlockedInboundIP {
	m.mu.RLock()
	defer m.mu.RUnlock()
	blocks := make([]BlockedInboundIP, 0, len(m.blockedInboundIPs))
	for _, block := range m.blockedInboundIPs {
		blocks = append(blocks, block)
	}
	return blocks
}

func (m *Manager) runConnectionCleanup() {
	ticker := time.NewTicker(udpCleanupInterval)
	defer func() {
		ticker.Stop()
		close(m.cleanupDone)
	}()
	for {
		select {
		case now := <-ticker.C:
			m.cleanupExpiredUDPFlows(now)
		case <-m.cleanupStop:
			return
		}
	}
}

func (m *Manager) cleanupExpiredUDPFlows(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	timeout := m.udpFlowTimeout
	if timeout <= 0 {
		timeout = defaultUDPFlowTimeout
	}
	removed := 0
	for key, flow := range m.udpFlows {
		if now.Sub(flow.LastSeenAt) > timeout {
			delete(m.udpFlows, key)
			removed++
		}
	}
	return removed
}

func (m *Manager) stopConnectionCleanup() {
	m.closeOnce.Do(func() {
		close(m.cleanupStop)
		<-m.cleanupDone
	})
}

func (m *Manager) clearTrackedConnections() []*activeTCPConnection {
	m.mu.Lock()
	defer m.mu.Unlock()
	connections := make([]*activeTCPConnection, 0, len(m.tcpConnections))
	for _, conn := range m.tcpConnections {
		connections = append(connections, conn)
	}
	clear(m.tcpConnections)
	clear(m.udpFlows)
	return connections
}

func (m *Manager) FeedTrafficSample(ctx context.Context, sample dpiengine.TrafficSample) dpi.Decision {
	m.mu.RLock()
	inspector := m.inspector
	if sample.Flow.UserID == 0 && sample.Flow.LeaseID != "" && sample.Flow.ProxyName != "" {
		if binding, ok := m.bindings[bindingKey(sample.Flow.LeaseID, sample.Flow.ProxyName)]; ok {
			sample.Flow.UserID = binding.UserID
			sample.Flow.TokenID = binding.TokenID
			sample.Flow.ClientID = binding.ClientID
			sample.Flow.RemotePort = binding.RemotePort
			if sample.Flow.ProxyType == "" {
				sample.Flow.ProxyType = binding.ProxyType
			}
		}
	}
	m.mu.RUnlock()
	if inspector == nil {
		return dpi.Allow()
	}
	return inspector.Inspect(ctx, sample)
}

func (m *Manager) bindingForLocked(leaseID, proxyName string) ProxyBinding {
	if binding, ok := m.bindings[bindingKey(leaseID, proxyName)]; ok {
		return binding
	}
	return ProxyBinding{LeaseID: leaseID, ProxyName: proxyName, ClientAddr: m.leaseClientAddresses[leaseID]}
}

func (m *Manager) SampleForBinding(binding ProxyBinding, direction dpiengine.Direction, payload []byte, localAddr, remoteAddr string) dpiengine.TrafficSample {
	return dpiengine.TrafficSample{
		Flow: dpiengine.FlowContext{
			UserID:     binding.UserID,
			TokenID:    binding.TokenID,
			ClientID:   binding.ClientID,
			LeaseID:    binding.LeaseID,
			ProxyName:  binding.ProxyName,
			ProxyType:  binding.ProxyType,
			RemotePort: binding.RemotePort,
			LocalAddr:  localAddr,
			RemoteAddr: remoteAddr,
		},
		Direction:      direction,
		Payload:        payload,
		PayloadLength:  len(payload),
		CapturedLength: len(payload),
	}
}

func (m *Manager) InspectTCP(ctx context.Context, sample dpihook.TrafficSample) dpihook.Decision {
	return toHookDecision(m.FeedTrafficSample(ctx, fromHookSample(sample)))
}

func (m *Manager) InspectUDP(ctx context.Context, sample dpihook.TrafficSample) dpihook.Decision {
	return toHookDecision(m.FeedTrafficSample(ctx, fromHookSample(sample)))
}

func fromHookSample(sample dpihook.TrafficSample) dpiengine.TrafficSample {
	return dpiengine.TrafficSample{
		Flow: dpiengine.FlowContext{
			LeaseID:    sample.Flow.LeaseID,
			ProxyName:  sample.Flow.ProxyName,
			ProxyType:  sample.Flow.ProxyType,
			LocalAddr:  sample.Flow.LocalAddr,
			RemoteAddr: sample.Flow.RemoteAddr,
			User:       sample.Flow.User,
			Metas:      sample.Flow.Metas,
		},
		Direction:      dpiengine.Direction(sample.Direction),
		Payload:        sample.Payload,
		PayloadLength:  sample.PayloadLength,
		CapturedLength: sample.CapturedLength,
		ObservedAt:     sample.ObservedAt,
	}
}

func toHookDecision(decision dpi.Decision) dpihook.Decision {
	return dpihook.Decision{
		Action: dpihook.Action(decision.Action),
		Reason: decision.Reason,
	}
}

func bindingKey(leaseID, proxyName string) string {
	return leaseID + "\x00" + proxyName
}

func splitAddr(addr string) (string, int) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return strings.TrimSpace(addr), 0
	}
	port, _ := strconv.Atoi(portText)
	return host, port
}

func valueOr(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func abortiveClose(closer io.Closer) {
	if tcpConn, ok := closer.(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
	}
	_ = closer.Close()
}
