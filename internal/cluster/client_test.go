package cluster

import (
	"testing"
	"time"
)

func TestNextReconnectDelayResetsAfterEstablishedConnection(t *testing.T) {
	if got := nextReconnectDelay(30*time.Second, true); got != time.Second {
		t.Fatalf("established connection must reset backoff, got %s", got)
	}
	if got := nextReconnectDelay(16*time.Second, false); got != 30*time.Second {
		t.Fatalf("backoff must cap at 30 seconds, got %s", got)
	}
}
