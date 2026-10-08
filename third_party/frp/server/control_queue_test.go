package server

import (
	"errors"
	"sync"
	"testing"

	pkgerr "github.com/fatedier/frp/pkg/errors"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/fatedier/frp/server/proxy"
)

func TestRegisterWorkConnRejectsClosedQueueWithoutPanicking(t *testing.T) {
	ctl := &Control{workConnCh: make(chan *proxy.WorkConn, 1), xl: xlog.New()}
	ctl.mu.Lock()
	ctl.workConnClosed = true
	close(ctl.workConnCh)
	ctl.mu.Unlock()
	if err := ctl.RegisterWorkConn(nil); !errors.Is(err, pkgerr.ErrCtlClosed) {
		t.Fatalf("closed queue returned success: %v", err)
	}
}

func TestWorkConnectionRegistrationCannotRaceQueueClosure(t *testing.T) {
	ctl := &Control{workConnCh: make(chan *proxy.WorkConn, 64), xl: xlog.New()}
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() { defer workers.Done(); _ = ctl.RegisterWorkConn(nil) }()
	}
	ctl.mu.Lock()
	ctl.workConnClosed = true
	close(ctl.workConnCh)
	ctl.mu.Unlock()
	workers.Wait()
}
