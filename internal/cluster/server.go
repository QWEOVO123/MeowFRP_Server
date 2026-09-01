package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"frp-control-server/internal/db"
	"frp-control-server/internal/dpi"
	"frp-control-server/internal/security"
	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type ControllerServer struct {
	store             NodeStore
	paths             PKIPaths
	material          *PKIMaterial
	httpServer        *http.Server
	grpcServer        *grpc.Server
	actualAddr        string
	mu                sync.RWMutex
	sessions          map[string]*nodeSession
	commandWaiters    map[string]chan CommandResult
	heartbeatInterval int
}

type nodeSession struct {
	nodeID        string
	send          chan Message
	connectedAt   time.Time
	lastHeartbeat time.Time
	capabilities  json.RawMessage
}

type NodeStore interface {
	ConsumeEnrollmentToken(context.Context, string) error
	UpsertEdgeNode(context.Context, db.EdgeNode) error
	GetEdgeNode(context.Context, string) (*db.EdgeNode, error)
	TouchEdgeNode(context.Context, string, string, string) error
}

type IdentitySnapshotStore interface {
	ListUsers(context.Context) ([]db.User, error)
	ListAccessTokens(context.Context) ([]db.AccessToken, error)
	ListUserResourcePolicies(context.Context) ([]db.UserResourcePolicy, error)
	ListAllPortGrants(context.Context) ([]db.PortGrant, error)
	ListDPIPolicies(context.Context) ([]dpi.Policy, error)
	ListBlockedInboundIPs(context.Context) ([]db.BlockedInboundIP, error)
}

type NodeControlStore interface {
	ListPendingNodeCommands(context.Context, string) ([]db.NodeCommandRecord, error)
	MarkNodeCommandDelivered(context.Context, string) error
	CompleteNodeCommand(context.Context, string, string, string, string) error
	RecordNodeEvent(context.Context, string, int64, string, string, string) (bool, error)
	ReplaceEdgeClientPresence(context.Context, string, []db.EdgeClientPresence) error
	RecordEdgeDPIEvent(context.Context, string, dpi.Event) error
}

type NodeTelemetryStore interface {
	ReplaceEdgeConnectionPresence(context.Context, string, []db.EdgeConnectionPresence) error
	UpsertEdgeNodeTraffic(context.Context, db.EdgeNodeTraffic) error
}

func NewControllerServer(store NodeStore, paths PKIPaths) *ControllerServer {
	return &ControllerServer{store: store, paths: paths, sessions: map[string]*nodeSession{}, commandWaiters: map[string]chan CommandResult{}, heartbeatInterval: 5}
}
func NewControllerServerWithMaterial(store NodeStore, material PKIMaterial) *ControllerServer {
	return &ControllerServer{store: store, material: &material, sessions: map[string]*nodeSession{}, commandWaiters: map[string]chan CommandResult{}, heartbeatInterval: 5}
}
func (s *ControllerServer) Addr() string { return s.actualAddr }
func (s *ControllerServer) SetHeartbeatInterval(seconds int) {
	if seconds < 2 {
		seconds = 2
	}
	if seconds > 60 {
		seconds = 60
	}
	s.mu.Lock()
	s.heartbeatInterval = seconds
	s.mu.Unlock()
}
func (s *ControllerServer) HeartbeatInterval() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.heartbeatInterval == 0 {
		return 5
	}
	return s.heartbeatInterval
}
func (s *ControllerServer) ConnectedNodes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		out = append(out, id)
	}
	return out
}
func (s *ControllerServer) SendCommand(command NodeCommand) bool {
	s.mu.RLock()
	session := s.sessions[command.NodeID]
	s.mu.RUnlock()
	if session == nil {
		return false
	}
	payload, _ := json.Marshal(command)
	select {
	case session.send <- Message{Type: "command", NodeID: command.NodeID, CommandID: command.CommandID, Payload: payload, SentAt: time.Now()}:
		return true
	default:
		return false
	}
}

// SendCommandAndWait delivers a sensitive online-only command without storing
// its payload in the command database. The caller owns the timeout policy.
func (s *ControllerServer) SendCommandAndWait(ctx context.Context, command NodeCommand) (CommandResult, error) {
	waiter := make(chan CommandResult, 1)
	s.mu.Lock()
	if s.sessions[command.NodeID] == nil {
		s.mu.Unlock()
		return CommandResult{}, errors.New("edge node is offline")
	}
	if _, exists := s.commandWaiters[command.CommandID]; exists {
		s.mu.Unlock()
		return CommandResult{}, errors.New("duplicate command id")
	}
	s.commandWaiters[command.CommandID] = waiter
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.commandWaiters, command.CommandID)
		s.mu.Unlock()
	}()
	if !s.SendCommand(command) {
		return CommandResult{}, errors.New("edge command channel is unavailable")
	}
	select {
	case result := <-waiter:
		return result, nil
	case <-ctx.Done():
		return CommandResult{}, ctx.Err()
	}
}

func (s *ControllerServer) NodeSession(nodeID string) (bool, json.RawMessage) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session := s.sessions[nodeID]
	if session == nil {
		return false, nil
	}
	return true, append(json.RawMessage(nil), session.capabilities...)
}

func (s *ControllerServer) deliverCommandResult(result CommandResult) bool {
	s.mu.RLock()
	waiter := s.commandWaiters[result.CommandID]
	s.mu.RUnlock()
	if waiter == nil {
		return false
	}
	select {
	case waiter <- result:
	default:
	}
	return true
}

func (s *ControllerServer) Start(ctx context.Context, addr string) error {
	material, err := s.pkiMaterial()
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(material.Certificate, material.PrivateKey)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(material.CACertificate) {
		return errors.New("invalid node CA")
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}
	s.grpcServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)), grpc.ForceServerCodec(jsonCodec{}))
	s.grpcServer.RegisterService(&controlServiceDesc, s)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			s.grpcServer.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
	s.httpServer = &http.Server{Addr: addr, Handler: mux, TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	_ = http2.ConfigureServer(s.httpServer, &http2.Server{})
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.actualAddr = listener.Addr().String()
	tlsListener := tls.NewListener(listener, tlsCfg)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.httpServer.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := s.httpServer.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("controller node endpoint: %v", err)
		}
	}()
	return nil
}

func (s *ControllerServer) pkiMaterial() (PKIMaterial, error) {
	if s.material != nil {
		return *s.material, nil
	}
	return LoadPKIMaterial(s.paths)
}

func (s *ControllerServer) enroll(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		writeClusterError(w, http.StatusUnauthorized, "enrollment token is required")
		return
	}
	var req EnrollmentRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeClusterError(w, http.StatusBadRequest, "invalid enrollment request")
		return
	}
	req.NodeName = strings.TrimSpace(req.NodeName)
	if req.NodeName == "" || ParseCSRPublicKey(req.CSR) != nil {
		writeClusterError(w, http.StatusBadRequest, "node name and valid CSR are required")
		return
	}
	plainNodeID, _, err := security.NewOpaqueToken("node_")
	if err != nil {
		writeClusterError(w, 500, err.Error())
		return
	}
	nodeID := plainNodeID[:min(37, len(plainNodeID))]
	material, err := s.pkiMaterial()
	if err != nil {
		writeClusterError(w, 500, err.Error())
		return
	}
	certPEM, serial, expires, err := SignNodeCSRMaterial(material, nodeID, []byte(req.CSR))
	if err != nil {
		writeClusterError(w, 400, err.Error())
		return
	}
	if err := s.store.ConsumeEnrollmentToken(r.Context(), security.TokenHash(token)); err != nil {
		writeClusterError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err := s.store.UpsertEdgeNode(r.Context(), db.EdgeNode{NodeID: nodeID, Name: req.NodeName, CertificateSerial: serial, CapabilitiesJSON: "{}"}); err != nil {
		writeClusterError(w, 500, err.Error())
		return
	}
	caPEM := material.CACertificate
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(EnrollmentResponse{NodeID: nodeID, Certificate: string(certPEM), CACertificate: string(caPEM), ExpiresAt: expires})
}

func (s *ControllerServer) Connect(stream grpc.ServerStream) error {
	peerInfo, ok := peer.FromContext(stream.Context())
	if !ok {
		return errors.New("missing peer identity")
	}
	tlsInfo, ok := peerInfo.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return errors.New("mTLS client certificate is required")
	}
	cert := tlsInfo.State.PeerCertificates[0]
	nodeID := cert.Subject.CommonName
	node, err := s.store.GetEdgeNode(stream.Context(), nodeID)
	if err != nil || node.Status != "active" || !strings.EqualFold(node.CertificateSerial, cert.SerialNumber.Text(16)) {
		return errors.New("edge node is not authorized")
	}
	session := &nodeSession{nodeID: nodeID, send: make(chan Message, 128), connectedAt: time.Now(), lastHeartbeat: time.Now()}
	s.mu.Lock()
	s.sessions[nodeID] = session
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.sessions[nodeID] == session {
			delete(s.sessions, nodeID)
		}
		s.mu.Unlock()
	}()
	writeErr := make(chan error, 1)
	go func() {
		for {
			select {
			case message := <-session.send:
				if err := stream.SendMsg(&message); err != nil {
					writeErr <- err
					return
				}
			case <-stream.Context().Done():
				return
			}
		}
	}()
	enqueue := func(message Message) error {
		select {
		case session.send <- message:
			return nil
		case err := <-writeErr:
			return err
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
	observedAddress := peerHost(peerInfo.Addr)
	welcomePayload, _ := json.Marshal(HeartbeatAck{IntervalSeconds: s.HeartbeatInterval(), ServerTime: time.Now(), ObservedAddress: observedAddress})
	if err := enqueue(Message{Type: "welcome", NodeID: nodeID, Payload: welcomePayload, SentAt: time.Now()}); err != nil {
		return err
	}
	if snapshot, err := s.identitySnapshotMessage(stream.Context(), nodeID); err == nil && snapshot != nil {
		if err := enqueue(*snapshot); err != nil {
			return err
		}
	}
	s.dispatchPendingCommands(stream.Context(), nodeID)
	lastPersist := time.Time{}
	for {
		var message Message
		if err := stream.RecvMsg(&message); err != nil {
			return err
		}
		capabilities := string(message.Capabilities)
		if capabilities == "" {
			capabilities = "{}"
		}
		now := time.Now()
		s.mu.Lock()
		if s.sessions[nodeID] == session {
			session.lastHeartbeat = now
			session.capabilities = append(session.capabilities[:0], message.Capabilities...)
		}
		s.mu.Unlock()
		if lastPersist.IsZero() || now.Sub(lastPersist) >= 30*time.Second {
			if err := s.store.TouchEdgeNode(stream.Context(), nodeID, peerInfo.Addr.String(), capabilities); err != nil {
				return err
			}
			lastPersist = now
		}
		if message.Type == "heartbeat" {
			var heartbeat HeartbeatPayload
			_ = json.Unmarshal(message.Payload, &heartbeat)
			if control, ok := s.store.(NodeControlStore); ok {
				clients := make([]db.EdgeClientPresence, 0, len(heartbeat.Clients))
				for _, client := range heartbeat.Clients {
					seen := now
					if client.LastSeenAt != nil {
						seen = *client.LastSeenAt
					}
					clients = append(clients, db.EdgeClientPresence{NodeID: nodeID, UserID: client.UserID, TokenID: client.TokenID, ClientID: client.ClientID, FRPCRunning: client.FRPCRunning, LastSeenAt: seen})
				}
				_ = control.ReplaceEdgeClientPresence(stream.Context(), nodeID, clients)
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
					_ = telemetry.ReplaceEdgeConnectionPresence(stream.Context(), nodeID, connections)
				}
				if heartbeat.Traffic != nil {
					traffic := heartbeat.Traffic
					_ = telemetry.UpsertEdgeNodeTraffic(stream.Context(), db.EdgeNodeTraffic{
						NodeID: nodeID, BytesInbound: traffic.BytesInbound, BytesOutbound: traffic.BytesOutbound,
						SamplesInbound: traffic.SamplesInbound, SamplesOutbound: traffic.SamplesOutbound,
						StartedAt: traffic.StartedAt, CapturedAt: traffic.CapturedAt,
					})
				}
			}
			ackPayload, _ := json.Marshal(HeartbeatAck{IntervalSeconds: s.HeartbeatInterval(), ServerTime: now, ObservedAddress: observedAddress})
			if err := enqueue(Message{Type: "heartbeat_ack", NodeID: nodeID, Sequence: message.Sequence, Payload: ackPayload, SentAt: now}); err != nil {
				return err
			}
			if message.Sequence%12 == 0 {
				if snapshot, err := s.identitySnapshotMessage(stream.Context(), nodeID); err == nil && snapshot != nil {
					if err := enqueue(*snapshot); err != nil {
						return err
					}
				}
			}
			s.dispatchPendingCommands(stream.Context(), nodeID)
		} else if message.Type == "event_batch" {
			var batch EventBatch
			if json.Unmarshal(message.Payload, &batch) == nil {
				acked := s.recordEventBatch(stream.Context(), nodeID, message.Sequence, batch)
				payload, _ := json.Marshal(EventAck{EventIDs: acked})
				if err := enqueue(Message{Type: "event_ack", NodeID: nodeID, Sequence: message.Sequence, Payload: payload, SentAt: now}); err != nil {
					return err
				}
			}
		} else if message.Type == "command_result" {
			var result CommandResult
			if json.Unmarshal(message.Payload, &result) == nil {
				if s.deliverCommandResult(result) {
					continue
				}
				if control, ok := s.store.(NodeControlStore); ok {
					encoded, _ := json.Marshal(result)
					_ = control.CompleteNodeCommand(stream.Context(), nodeID, result.CommandID, result.Status, string(encoded))
				}
			}
		}
	}
}

func peerHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(addr.String(), "[]")
}

func (s *ControllerServer) identitySnapshotMessage(ctx context.Context, nodeID string) (*Message, error) {
	if _, ok := s.store.(IdentitySnapshotStore); !ok {
		return nil, nil
	}
	store := s.store.(IdentitySnapshotStore)
	users, err := store.ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	tokens, err := store.ListAccessTokens(ctx)
	if err != nil {
		return nil, err
	}
	policies, err := store.ListUserResourcePolicies(ctx)
	if err != nil {
		return nil, err
	}
	grants, err := store.ListAllPortGrants(ctx)
	if err != nil {
		return nil, err
	}
	dpiPolicies, err := store.ListDPIPolicies(ctx)
	if err != nil {
		return nil, err
	}
	blocked, err := store.ListBlockedInboundIPs(ctx)
	if err != nil {
		return nil, err
	}
	snapshot := IdentitySnapshot{Revision: time.Now().UnixNano(), Policies: policies, Grants: grants, DPIPolicies: dpiPolicies, BlockedIPs: blocked}
	for _, user := range users {
		snapshot.Users = append(snapshot.Users, SnapshotUser{user.ID, user.Username, user.Role, user.Status, user.BanReason})
	}
	for _, token := range tokens {
		snapshot.Tokens = append(snapshot.Tokens, SnapshotToken{token.ID, token.UserID, token.Name, token.TokenHash, token.Status, token.BanReason, token.MaxProxyCount, token.ExpiresAt})
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	return &Message{Type: "identity_snapshot", NodeID: nodeID, Revision: snapshot.Revision, Payload: payload, SentAt: time.Now()}, nil
}

func (s *ControllerServer) dispatchPendingCommands(ctx context.Context, nodeID string) {
	control, ok := s.store.(NodeControlStore)
	if !ok {
		return
	}
	commands, err := control.ListPendingNodeCommands(ctx, nodeID)
	if err != nil {
		return
	}
	for _, record := range commands {
		command := NodeCommand{CommandID: record.CommandID, NodeID: nodeID, Command: record.CommandType, Payload: json.RawMessage(record.PayloadJSON), ExpiresAt: record.ExpiresAt}
		if s.SendCommand(command) {
			_ = control.MarkNodeCommandDelivered(ctx, record.CommandID)
		}
	}
}
func (s *ControllerServer) recordEventBatch(ctx context.Context, nodeID string, sequence int64, batch EventBatch) []string {
	control, ok := s.store.(NodeControlStore)
	if !ok {
		return nil
	}
	acked := make([]string, 0, len(batch.Events))
	for index, event := range batch.Events {
		if event.EventID == "" {
			continue
		}
		inserted, err := control.RecordNodeEvent(ctx, nodeID, sequence*1000+int64(index), event.EventID, event.EventType, string(event.Payload))
		if err != nil {
			continue
		}
		if inserted && event.EventType == "dpi_event" {
			var dpiEvent dpi.Event
			if json.Unmarshal(event.Payload, &dpiEvent) == nil {
				_ = control.RecordEdgeDPIEvent(ctx, nodeID, dpiEvent)
			}
		}
		acked = append(acked, event.EventID)
	}
	return acked
}

func writeClusterError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": message})
}
