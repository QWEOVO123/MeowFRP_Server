package proxy

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/fatedier/frp/pkg/dpihook"
	"github.com/fatedier/frp/pkg/msg"
)

const maxDPIInspectBytes = 8192

var errDPIBlocked = errors.New("blocked by dpi")

type dpiTCPConn struct {
	net.Conn
	ctx       context.Context
	flow      dpihook.FlowContext
	inspected int
	blocked   bool
}

func (c *dpiTCPConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n <= 0 || c.blocked {
		return n, err
	}
	inspector := dpihook.Current()
	if inspector == nil || c.inspected >= maxDPIInspectBytes {
		return n, err
	}
	sampleLen := n
	if remaining := maxDPIInspectBytes - c.inspected; sampleLen > remaining {
		sampleLen = remaining
	}
	payload := make([]byte, sampleLen)
	copy(payload, p[:sampleLen])
	c.inspected += sampleLen
	decision := inspector.InspectTCP(c.ctx, dpihook.TrafficSample{
		Flow:           c.flow,
		Direction:      dpihook.DirectionInbound,
		Payload:        payload,
		PayloadLength:  n,
		CapturedLength: sampleLen,
		ObservedAt:     time.Now(),
	})
	if decision.Action == dpihook.ActionBlock {
		c.blocked = true
		_ = c.Conn.Close()
		return 0, errDPIBlocked
	}
	return n, err
}

func (pxy *BaseProxy) wrapDPIUserConn(userConn net.Conn, proxyType string) net.Conn {
	if dpihook.Current() == nil {
		return userConn
	}
	userInfo := pxy.GetUserInfo()
	return &dpiTCPConn{
		Conn: userConn,
		ctx:  pxy.Context(),
		flow: dpihook.FlowContext{
			User:       userInfo.User,
			Metas:      userInfo.Metas,
			LeaseID:    userInfo.Metas["lease_id"],
			ProxyName:  pxy.GetName(),
			ProxyType:  proxyType,
			LocalAddr:  userConn.LocalAddr().String(),
			RemoteAddr: userConn.RemoteAddr().String(),
		},
	}
}

func (pxy *UDPProxy) inspectUDPMessage(udpMsg *msg.UDPPacket) bool {
	if udpMsg == nil || len(udpMsg.Content) == 0 {
		return true
	}
	userInfo := pxy.GetUserInfo()
	remoteAddr := ""
	if udpMsg.RemoteAddr != nil {
		remoteAddr = udpMsg.RemoteAddr.String()
	}
	localAddr := ""
	if pxy.udpConn != nil && pxy.udpConn.LocalAddr() != nil {
		localAddr = pxy.udpConn.LocalAddr().String()
	}
	connectionInfo := dpihook.ConnectionInfo{
		Protocol:   "udp",
		User:       userInfo.User,
		Metas:      userInfo.Metas,
		LeaseID:    userInfo.Metas["lease_id"],
		ProxyName:  pxy.GetName(),
		ProxyType:  pxy.cfg.Type,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		ObservedAt: time.Now(),
	}
	if observer := dpihook.CurrentConnectionObserver(); observer != nil {
		if observer.IsInboundBlocked(pxy.Context(), connectionInfo) {
			return false
		}
		observer.ObserveUDPFlow(pxy.Context(), connectionInfo)
	}
	inspector := dpihook.Current()
	if inspector == nil {
		return true
	}
	payload := make([]byte, len(udpMsg.Content))
	copy(payload, udpMsg.Content)
	decision := inspector.InspectUDP(pxy.Context(), dpihook.TrafficSample{
		Flow: dpihook.FlowContext{
			User:       userInfo.User,
			Metas:      userInfo.Metas,
			LeaseID:    userInfo.Metas["lease_id"],
			ProxyName:  pxy.GetName(),
			ProxyType:  pxy.cfg.Type,
			LocalAddr:  localAddr,
			RemoteAddr: remoteAddr,
		},
		Direction:      dpihook.DirectionInbound,
		Payload:        payload,
		PayloadLength:  len(payload),
		CapturedLength: len(payload),
		ObservedAt:     time.Now(),
	})
	return decision.Action != dpihook.ActionBlock
}
