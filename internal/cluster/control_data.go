package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"frp-control-server/internal/db"
	"log"
	"time"
)

// SQL/report work stays off the heartbeat receive loop. Events remain on disk
// until durable ACK; lost command result persistence is retried idempotently.
func (s *ControllerServer) persistControlData(ctx context.Context, session *nodeSession, message Message) {
	nodeID := session.nodeID
	switch message.Type {
	case "report":
		s.persistReport(ctx, nodeID, message)
	case "event_batch":
		var batch EventBatch
		if json.Unmarshal(message.Payload, &batch) != nil {
			return
		}
		acked := s.recordEventBatch(ctx, nodeID, message.Sequence, batch)
		payload, _ := json.Marshal(EventAck{EventIDs: acked})
		select {
		case session.send <- Message{Type: "event_ack", NodeID: nodeID, Sequence: message.Sequence, Payload: payload, SentAt: time.Now()}:
		case <-ctx.Done():
		}
	case "command_result":
		var result CommandResult
		if json.Unmarshal(message.Payload, &result) != nil {
			return
		}
		if control, ok := s.store.(NodeControlStore); ok {
			encoded, _ := json.Marshal(result)
			if err := control.CompleteNodeCommand(ctx, nodeID, result.CommandID, result.Status, string(encoded)); err != nil && !errors.Is(err, db.ErrNotFound) {
				log.Printf("persist edge command result node=%s id=%s: %v", nodeID, result.CommandID, err)
				result.Status = "retry"
				result.Error = "edge replied, controller persistence unavailable; safe retry pending"
			} else if err == nil {
				s.RefreshNode(ctx, nodeID)
			}
		}
		s.deliverCommandResult(result)
	}
}
