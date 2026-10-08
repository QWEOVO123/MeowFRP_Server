package cluster

import (
	"context"
	"encoding/json"
	"frp-control-server/internal/db"
	"log"
	"time"
)

func (s *ControllerServer) persistReport(ctx context.Context, nodeID string, message Message) {
	now := time.Now()
	var heartbeat HeartbeatPayload
	if err := json.Unmarshal(message.Payload, &heartbeat); err != nil {
		s.deliverCommandResult(CommandResult{CommandID: message.CommandID, Status: "failed", Error: err.Error()})
		return
	}
	if heartbeat.ReportError != "" {
		s.deliverCommandResult(CommandResult{CommandID: message.CommandID, Status: "failed", Error: heartbeat.ReportError})
		return
	}
	if control, ok := s.store.(NodeControlStore); ok {
		clients := make([]db.EdgeClientPresence, 0, len(heartbeat.Clients))
		for _, client := range heartbeat.Clients {
			seen := now
			if client.LastSeenAt != nil {
				seen = *client.LastSeenAt
			}
			clients = append(clients, db.EdgeClientPresence{NodeID: nodeID, UserID: client.UserID, TokenID: client.TokenID, ClientID: client.ClientID, FRPCRunning: client.FRPCRunning, LastSeenAt: seen})
		}
		if err := control.ReplaceEdgeClientPresence(ctx, nodeID, clients); err != nil {
			s.deliverCommandResult(CommandResult{CommandID: message.CommandID, Status: "failed", Error: err.Error()})
			log.Printf("edge report persistence node=%s: %v", nodeID, err)
			return
		}
	}
	if telemetry, ok := s.store.(NodeTelemetryStore); ok {
		if heartbeat.ReportingVersion > 0 {
			connections := make([]db.EdgeConnectionPresence, 0, len(heartbeat.Connections))
			if heartbeat.ConnectionsReportingEnabled {
				for _, connection := range heartbeat.Connections {
					connections = append(connections, db.EdgeConnectionPresence{
						NodeID: nodeID, ConnectionID: connection.ID, Protocol: connection.Protocol,
						UserID: connection.UserID, TokenID: connection.TokenID, ClientID: connection.ClientID,
						ClientAddr: connection.ClientAddr, LeaseID: connection.LeaseID, ProxyName: connection.ProxyName,
						ProxyType: connection.ProxyType, RemotePort: connection.RemotePort, InboundAddr: connection.InboundAddr,
						InboundIP: connection.InboundIP, InboundPort: connection.InboundPort, ServerAddr: connection.ServerAddr,
						OpenedAt: connection.OpenedAt, LastSeenAt: connection.LastSeenAt, CanTerminate: connection.CanTerminate,
					})
				}
			}
			if err := telemetry.ReplaceEdgeConnectionPresence(ctx, nodeID, connections); err != nil {
				s.deliverCommandResult(CommandResult{CommandID: message.CommandID, Status: "failed", Error: err.Error()})
				log.Printf("edge report persistence node=%s: %v", nodeID, err)
				return
			}
		}
		if heartbeat.Traffic != nil {
			traffic := heartbeat.Traffic
			if err := telemetry.UpsertEdgeNodeTraffic(ctx, db.EdgeNodeTraffic{
				NodeID: nodeID, BytesInbound: traffic.BytesInbound, BytesOutbound: traffic.BytesOutbound,
				SamplesInbound: traffic.SamplesInbound, SamplesOutbound: traffic.SamplesOutbound,
				StartedAt: traffic.StartedAt, CapturedAt: traffic.CapturedAt,
			}); err != nil {
				s.deliverCommandResult(CommandResult{CommandID: message.CommandID, Status: "failed", Error: err.Error()})
				log.Printf("edge report persistence node=%s: %v", nodeID, err)
				return
			}
		}
	}
	s.deliverCommandResult(CommandResult{CommandID: message.CommandID, Status: "succeeded"})
}
