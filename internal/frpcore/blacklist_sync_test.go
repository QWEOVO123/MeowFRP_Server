package frpcore

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/fatedier/frp/pkg/dpihook"
)

func TestSynchronizedInboundBanClosesExistingAndRejectsNewTraffic(t *testing.T) {
	m := NewManager(nil)
	t.Cleanup(func() { _ = m.Close() })
	ctx := context.Background()
	info := dpihook.ConnectionInfo{Protocol: "tcp", LeaseID: "demo", ProxyName: "ssh", RemoteAddr: "192.0.2.1:50000"}
	user, peer := net.Pipe()
	work, workPeer := net.Pipe()
	t.Cleanup(func() { _ = peer.Close(); _ = workPeer.Close() })
	id := m.RegisterTCPConnection(ctx, info, user, work)
	other := info
	other.RemoteAddr = "192.0.2.2:50000"
	otherUser, otherPeer := net.Pipe()
	t.Cleanup(func() { _ = otherPeer.Close() })
	otherID := m.RegisterTCPConnection(ctx, other, otherUser, nil)
	m.ObserveUDPFlow(ctx, info)
	stamp := time.Now().Add(-time.Hour)
	m.EnforceBlockedInboundIP(BlockedInboundIP{IP: "192.0.2.1", Reason: "controller global", CreatedAt: stamp})
	if !m.IsInboundBlocked(ctx, info) || m.IsInboundBlocked(ctx, other) {
		t.Fatal("inbound filtering scope incorrect")
	}
	m.mu.RLock()
	_, blockedStillTracked := m.tcpConnections[id]
	_, unrelatedStillTracked := m.tcpConnections[otherID]
	udpCount := len(m.udpFlows)
	m.mu.RUnlock()
	if blockedStillTracked || !unrelatedStillTracked || udpCount != 0 {
		t.Fatal("ban did not close matching TCP/UDP only")
	}
	buf := make([]byte, 1)
	if _, err := peer.Read(buf); err == nil {
		t.Fatal("inbound TCP socket still open")
	}
	if _, err := workPeer.Read(buf); err == nil {
		t.Fatal("work socket still open")
	}
	blocks := m.ListBlockedInboundIPs()
	if len(blocks) != 1 || !blocks[0].CreatedAt.Equal(stamp) {
		t.Fatal("controller timestamp lost")
	}
	m.UnblockInboundIP("192.0.2.1")
	if m.IsInboundBlocked(ctx, info) {
		t.Fatal("unblock failed")
	}
}
