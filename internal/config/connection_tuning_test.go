package config

import "testing"

func TestConnectionTuningRanges(t *testing.T) {
	for _, value := range []ConnectionTuning{{}, {TCPKeepaliveSeconds: -1, HeartbeatTimeoutSeconds: -1}, {MTLSHandshakeTimeoutSeconds: 120, MaxPoolCount: 1024}} {
		if err := ValidateConnectionTuning(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []ConnectionTuning{{TCPKeepaliveSeconds: -2}, {MTLSHandshakeTimeoutSeconds: 121}, {MaxPoolCount: 1025}, {UserConnectionTimeoutSeconds: -1}} {
		if ValidateConnectionTuning(value) == nil {
			t.Fatal("invalid tuning accepted")
		}
	}
}
