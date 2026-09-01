package edgestate

import (
	"context"
	"strings"
	"time"

	"frp-control-server/internal/security"
)

// RuntimeLogWriter mirrors service log lines into the reliable Edge event
// queue. Queue failures are intentionally silent to avoid recursive logging.
type RuntimeLogWriter struct {
	store   *Store
	enabled func() bool
}

func NewRuntimeLogWriter(store *Store, enabled func() bool) *RuntimeLogWriter {
	return &RuntimeLogWriter{store: store, enabled: enabled}
}

func (w *RuntimeLogWriter) Write(p []byte) (int, error) {
	if w == nil || w.store == nil || w.enabled == nil || !w.enabled() {
		return len(p), nil
	}
	for _, line := range strings.Split(string(p), "\n") {
		message := strings.TrimSpace(line)
		if message == "" {
			continue
		}
		runes := []rune(message)
		if len(runes) > 4096 {
			message = string(runes[:4096])
		}
		eventID, _, err := security.NewOpaqueToken("log_")
		if err != nil {
			continue
		}
		_ = w.store.QueueEvent(context.Background(), eventID, "runtime_log", map[string]any{
			"message":    message,
			"created_at": time.Now().UTC(),
		})
	}
	return len(p), nil
}
