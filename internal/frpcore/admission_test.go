package frpcore

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"frp-control-server/internal/db"
	"github.com/fatedier/frp/pkg/dpihook"
	splugin "github.com/fatedier/frp/pkg/plugin/server"
)

func admissionTestManager(t *testing.T) (*Manager, splugin.UserInfo) {
	t.Helper()
	m := NewManager(nil)
	t.Cleanup(func() { _ = m.Close() })
	m.RememberRuntimeLease(db.RuntimeLease{LeaseID: "lease", TokenID: 9, ClientID: "desktop", RuntimeTokenHash: "hash", Status: "active"})
	return m, splugin.UserInfo{RunID: "run", Metas: map[string]string{"lease_id": "lease"}}
}

func TestProxyLifecycleCountsRegisteredPortsNotTraffic(t *testing.T) {
	m, user := admissionTestManager(t)
	hook := m.proxyLifecycle()
	release, err := hook.Begin(user)
	if err != nil {
		t.Fatal(err)
	}
	hook.Opened(user, "tcp")
	hook.Opened(user, "udp")
	release()
	if got := m.ClientProxyCount(9, "desktop"); got != 2 {
		t.Fatalf("idle registered ports=%d", got)
	}
	// Repeated notification and redundant close may not inflate/negate counts.
	hook.Opened(user, "tcp")
	if got := m.ClientProxyCount(9, "desktop"); got != 2 {
		t.Fatalf("duplicate open count=%d", got)
	}
	m.SetAdmissionClosed(true)
	if got := m.ClientProxyCount(9, "desktop"); got != 2 {
		t.Fatalf("fault removed active ports=%d", got)
	}
	m.SetAdmissionClosed(false)
	if release, err := hook.Begin(user); err == nil {
		release()
		t.Fatal("recovering client opened port before completing drain")
	}
	m.FinishClientDrain(9, "desktop")
	if !m.ClientDraining(9, "desktop") {
		t.Fatal("client with open ports finished drain")
	}
	hook.Closed(user, "tcp")
	hook.Closed(user, "tcp")
	if got := m.ClientProxyCount(9, "desktop"); got != 1 {
		t.Fatalf("close count=%d", got)
	}
	hook.Closed(user, "udp")
	if got := m.ClientProxyCount(9, "desktop"); got != 0 {
		t.Fatalf("final count=%d", got)
	}
	m.FinishClientDrain(9, "desktop")
	if m.ClientDraining(9, "desktop") {
		t.Fatal("zero-proxy drain did not finish")
	}
	if _, ok := m.ExistingRuntime("lease", "hash"); ok {
		t.Fatal("finished drain retained old runtime credentials")
	}
}

func TestAdmissionWriteFenceWaitsForInFlightRegistration(t *testing.T) {
	m, user := admissionTestManager(t)
	hook := m.proxyLifecycle()
	release, err := hook.Begin(user)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { m.SetAdmissionClosed(true); close(done) }()
	select {
	case <-done:
		release()
		t.Fatal("fault crossed unfinished registration")
	case <-time.After(20 * time.Millisecond):
	}
	hook.Opened(user, "port")
	release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("write fence did not finish")
	}
	if got := m.ClientProxyCount(9, "desktop"); got != 1 {
		t.Fatalf("registration lost behind fence=%d", got)
	}
	if release, err := hook.Begin(user); err == nil {
		release()
		t.Fatal("registration passed closed fence")
	}
}

func TestPausedAdmissionDoesNotMakeClientsDrain(t *testing.T) {
	m, user := admissionTestManager(t)
	m.PauseAdmission()
	if m.ClientDraining(9, "desktop") {
		t.Fatal("brief outage made drain sticky")
	}
	if release, err := m.proxyLifecycle().Begin(user); err == nil {
		release()
		t.Fatal("pause allowed registration")
	}
	m.SetAdmissionClosed(false)
	release, err := m.proxyLifecycle().Begin(user)
	if err != nil {
		t.Fatal("brief recovery rejected existing session:", err)
	}
	release()
}

func TestFaultFenceDoesNotCloseExistingTCPDataConnection(t *testing.T) {
	m, _ := admissionTestManager(t)
	userConn, userPeer := net.Pipe()
	workConn, workPeer := net.Pipe()
	defer userPeer.Close()
	defer workPeer.Close()
	m.BindProxy(ProxyBinding{LeaseID: "lease", TokenID: 9, ClientID: "desktop", ProxyName: "tcp", ProxyType: "tcp"})
	m.RegisterTCPConnection(context.Background(), dpihook.ConnectionInfo{LeaseID: "lease", ProxyName: "tcp", ProxyType: "tcp"}, userConn, workConn)
	m.SetAdmissionClosed(true)
	if got := len(m.ListConnections(time.Minute)); got != 1 {
		t.Fatalf("fault killed tracked connection: %d", got)
	}
	_ = userConn.SetReadDeadline(time.Now().Add(time.Second))
	go func() { _, _ = userPeer.Write([]byte("x")) }()
	buffer := make([]byte, 1)
	if _, err := userConn.Read(buffer); err != nil || buffer[0] != 'x' {
		t.Fatalf("existing data path stopped: %v", err)
	}
}

func TestConcurrentProxyLifecycleHasNoLeakedCounts(t *testing.T) {
	m, user := admissionTestManager(t)
	hook := m.proxyLifecycle()
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			u := user
			u.RunID = string(rune('a' + i))
			release, err := hook.Begin(u)
			if err != nil {
				t.Error(err)
				return
			}
			hook.Opened(u, "tcp")
			release()
			hook.Closed(u, "tcp")
		}(i)
	}
	workers.Wait()
	if got := m.ClientProxyCount(9, "desktop"); got != 0 {
		t.Fatalf("count leaked=%d", got)
	}
}
