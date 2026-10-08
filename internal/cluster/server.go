package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
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
	forgottenNodes        map[string]bool
	nodeCatalog           map[string]db.EdgeNode
	databaseFault         bool
	databaseSuspect       bool
	store                 NodeStore
	paths                 PKIPaths
	material              *PKIMaterial
	httpServer            *http.Server
	grpcServer            *grpc.Server
	actualAddr            string
	mu                    sync.RWMutex
	syncMu                sync.Mutex
	sessions              map[string]*nodeSession
	commandWaiters        map[string]chan CommandResult
	heartbeatInterval     int
	identityChanges       chan struct{}
	handshakeTimeout      time.Duration
	disableSessionTickets bool
}

type nodeSession struct {
	admissionProtocol int
	blockedIPs        map[string]db.BlockedInboundIP
	cancel            context.CancelFunc
	nodeID            string
	send              chan Message
	connectedAt       time.Time
	lastHeartbeat     time.Time
	capabilities      json.RawMessage
	pendingRevision   int64
	appliedRevision   int64
	syncStarted       time.Time
	done              <-chan struct{}
	cacheSessionID    string
	bootID            string
	cacheProtocol     int
	needsFull         bool
	needsBlockedIPs   bool
	pendingIdentity   *IdentitySnapshot
	cacheReady        bool
	baselineActive    bool
	baselineCursor    int64
	pendingCursor     int64
	pendingPayload    []byte
	chunkIndex        int
	chunkTotal        int
	applyProgress     int64
}

type IdentityCacheStore interface {
	NextIdentityRevision(context.Context) (int64, error)
	ResetNodeIdentityCache(context.Context, string, string, string) error
	MarkUserIdentityDirty(context.Context, int64) error
	PendingNodeIdentityUsers(context.Context, string, string) ([]int64, error)
	PrepareNodeIdentityCache(context.Context, string, string, int64, []int64) error
	ConfirmNodeIdentityCache(context.Context, string, string, int64, []int64, []int64, bool) error
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
	return &ControllerServer{store: store, paths: paths, sessions: map[string]*nodeSession{}, commandWaiters: map[string]chan CommandResult{}, heartbeatInterval: 5, identityChanges: make(chan struct{}, 1)}
}
func NewControllerServerWithMaterial(store NodeStore, material PKIMaterial) *ControllerServer {
	return &ControllerServer{store: store, material: &material, sessions: map[string]*nodeSession{}, commandWaiters: map[string]chan CommandResult{}, heartbeatInterval: 5, identityChanges: make(chan struct{}, 1)}
}
func (s *ControllerServer) Addr() string { return s.actualAddr }

// ConfigureTransport is only called before Start; changes require restart.
func (s *ControllerServer) ConfigureTransport(handshakeTimeout time.Duration, disableSessionTickets bool) {
	s.handshakeTimeout = handshakeTimeout
	s.disableSessionTickets = disableSessionTickets
}
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
	now := time.Now()
	for id, session := range s.sessions {
		if s.sessionAliveLocked(session, now) {
			out = append(out, id)
		}
	}
	return out
}
func (s *ControllerServer) DisconnectNode(nodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if session := s.sessions[nodeID]; session != nil {
		if session.cancel != nil {
			session.cancel()
		}
		delete(s.sessions, nodeID)
	}
}

func (s *ControllerServer) SendCommand(command NodeCommand) bool {
	s.mu.RLock()
	session := s.sessions[command.NodeID]
	alive := s.sessionAliveLocked(session, time.Now())
	s.mu.RUnlock()
	if !alive {
		return false
	}
	payload, _ := json.Marshal(command)
	select {
	case session.send <- Message{Type: "command", NodeID: command.NodeID, CommandID: command.CommandID, Payload: payload, SentAt: time.Now()}:
		return true
	default:
		if session.cancel != nil {
			session.cancel()
		}
		return false
	}
}

// SendCommandAndWait awaits the online edge's reply. It does not persist any
// payload itself: ordinary commands are queued by callers, while sensitive
// commands remain memory-only. The caller owns the timeout policy.
func (s *ControllerServer) SendCommandAndWait(ctx context.Context, command NodeCommand) (CommandResult, error) {
	waiter := make(chan CommandResult, 1)
	s.mu.Lock()
	if !s.sessionAliveLocked(s.sessions[command.NodeID], time.Now()) {
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
	if !s.sessionAliveLocked(session, time.Now()) {
		return false, nil
	}
	return true, append(json.RawMessage(nil), session.capabilities...)
}

func (s *ControllerServer) sessionAliveLocked(session *nodeSession, now time.Time) bool {
	if session == nil || session.lastHeartbeat.IsZero() {
		return false
	}
	select {
	case <-session.done:
		return false
	default:
	}
	interval := s.heartbeatInterval
	if interval == 0 {
		interval = 5
	}
	timeout := heartbeatTimeout(int64(interval))
	return now.Sub(session.lastHeartbeat) <= timeout
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
	if catalog, ok := s.store.(interface {
		ListEdgeNodes(context.Context) ([]db.EdgeNode, error)
	}); ok {
		readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		nodes, err := catalog.ListEdgeNodes(readCtx)
		cancel()
		if err != nil {
			log.Printf("load controller node catalog: %v", err)
			s.SetDatabaseSuspect(true)
			s.SetDatabaseFault(true)
		} else {
			s.ReplaceNodeCatalog(nodes)
		}
	}
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
	tlsCfg.SessionTicketsDisabled = s.disableSessionTickets
	s.grpcServer = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)), grpc.ForceServerCodec(jsonCodec{}), grpc.MaxRecvMsgSize(maxControlMessageBytes), grpc.MaxSendMsgSize(maxControlMessageBytes))
	s.grpcServer.RegisterService(&controlServiceDesc, s)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			s.grpcServer.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
	handshakeTimeout := s.handshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = 10 * time.Second
	}
	s.httpServer = &http.Server{Addr: addr, Handler: mux, TLSConfig: tlsCfg, ReadHeaderTimeout: handshakeTimeout, IdleTimeout: 2 * time.Minute}
	_ = http2.ConfigureServer(s.httpServer, &http2.Server{})
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.actualAddr = listener.Addr().String()
	go s.runIdentityPushes(ctx)
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
	node, err := s.authorizedNode(stream.Context(), nodeID)
	if err != nil || node.Status != "active" || !strings.EqualFold(node.CertificateSerial, cert.SerialNumber.Text(16)) {
		return errors.New("edge node is not authorized")
	}
	sessionCtx, cancelSession := context.WithCancel(stream.Context())
	defer cancelSession()
	session := &nodeSession{nodeID: nodeID, send: make(chan Message, 128), connectedAt: time.Now(), lastHeartbeat: time.Now(), cancel: cancelSession, done: sessionCtx.Done()}
	s.mu.Lock()
	if previous := s.sessions[nodeID]; previous != nil && previous.cancel != nil {
		previous.cancel()
	}
	s.sessions[nodeID] = session
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.sessions[nodeID] == session {
			delete(s.sessions, nodeID)
		}
		s.mu.Unlock()
	}()
	// Recheck after registration to close the race with an administrator deleting
	// the node between the initial lookup and the session being registered.
	node, err = s.authorizedNode(sessionCtx, nodeID)
	if err != nil || node.Status != "active" || !strings.EqualFold(node.CertificateSerial, cert.SerialNumber.Text(16)) {
		return errors.New("edge node is not authorized")
	}
	writeErr := make(chan error, 1)
	go func() {
		for {
			select {
			case message := <-session.send:
				if message.Type == "identity_chunk" || message.Type == "identity_snapshot" {
					s.mu.Lock()
					session.syncStarted = time.Now() // Starts on transmission, not queueing.
					s.mu.Unlock()
				}
				if err := stream.SendMsg(&message); err != nil {
					writeErr <- err
					return
				}
			case <-sessionCtx.Done():
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
		case <-sessionCtx.Done():
			return sessionCtx.Err()
		}
	}
	type receiveResult struct {
		message Message
		err     error
	}
	received := make(chan receiveResult)
	go func() {
		for {
			var message Message
			err := stream.RecvMsg(&message)
			select {
			case received <- receiveResult{message, err}:
			case <-sessionCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	// The edge first reports its process boot epoch. Cached identities are never
	// assumed to survive a restart; reconnect also requires a fresh full ACK.
	helloTimer := time.NewTimer(10 * time.Second)
	defer helloTimer.Stop()
	select {
	case first := <-received:
		if first.err != nil {
			return first.err
		}
		if first.message.Type != "hello" || first.message.NodeID != nodeID {
			return errors.New("edge hello identity mismatch")
		}
		if len(first.message.BootID) > 128 {
			return errors.New("invalid edge boot epoch")
		}
		session.bootID = first.message.BootID
		session.cacheProtocol = first.message.CacheProtocol
		session.admissionProtocol = first.message.AdmissionProtocol
		if session.cacheProtocol >= 2 && session.bootID == "" {
			return errors.New("edge boot epoch is required")
		}
		s.mu.Lock()
		session.capabilities = first.message.Capabilities
		s.mu.Unlock()
	case <-helloTimer.C:
		return errors.New("edge startup hello timed out")
	case <-sessionCtx.Done():
		return sessionCtx.Err()
	}
	cacheSessionID, _, err := security.NewOpaqueToken("cache_")
	if err != nil {
		return err
	}
	s.mu.Lock()
	session.cacheSessionID = cacheSessionID
	s.mu.Unlock()
	observedAddress := peerHost(peerInfo.Addr)
	protocol := 2
	if session.cacheProtocol >= 3 {
		protocol = 3
	}
	welcomePayload, _ := json.Marshal(HeartbeatAck{ControllerFault: s.DatabaseFault(), IdentityProtocol: protocol, IntervalSeconds: s.HeartbeatInterval(), ServerTime: time.Now(), ObservedAddress: observedAddress})
	if err := enqueue(Message{Type: "welcome", NodeID: nodeID, CacheSessionID: cacheSessionID, Payload: welcomePayload, SentAt: time.Now()}); err != nil {
		return err
	}
	if session.cacheProtocol < 3 {
		err = func() error {
			s.syncMu.Lock()
			defer s.syncMu.Unlock()
			if cache, ok := s.store.(IdentityCacheStore); ok {
				if err := cache.ResetNodeIdentityCache(sessionCtx, nodeID, cacheSessionID, session.bootID); err != nil {
					return err
				}
			}
			s.mu.Lock()
			session.cacheReady = true
			s.mu.Unlock()
			log.Printf("edge started/reconnected node=%s boot=%s cache associations reset; full synchronization required", nodeID, session.bootID)
			snapshot, err := s.identitySnapshotMessage(stream.Context(), nodeID)
			if err != nil {
				return fmt.Errorf("build initial identity snapshot: %w", err)
			}
			if snapshot != nil {
				if err := s.enqueueIdentity(sessionCtx, session, snapshot); err != nil {
					return err
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	} else {
		s.mu.Lock()
		session.syncStarted = time.Now()
		s.mu.Unlock()
		log.Printf("edge node=%s boot=%s waiting for cache-cleared acknowledgement session=%s", nodeID, session.bootID, cacheSessionID)
	}
	s.dispatchPendingCommands(stream.Context(), nodeID)
	lastPersist := time.Time{}
	telemetryJobs := make(chan Message, 16)
	touchJobs := make(chan string, 1)
	go func() {
		for {
			select {
			case <-sessionCtx.Done():
				return
			case message := <-telemetryJobs:
				ctx, cancel := context.WithTimeout(sessionCtx, 3*time.Second)
				s.persistControlData(ctx, session, message)
				cancel()
			case capabilities := <-touchJobs:
				ctx, cancel := context.WithTimeout(sessionCtx, time.Second)
				err := s.store.TouchEdgeNode(ctx, nodeID, peerInfo.Addr.String(), capabilities)
				cancel()
				if err != nil {
					log.Printf("persist edge heartbeat node=%s: %v", nodeID, err)
				}
			}
		}
	}()
	// MySQL reset/ACK transactions must not block control heartbeat replies.
	identityJobs := make(chan Message, 128)
	identityErr := make(chan error, 1)
	go func() {
		for {
			select {
			case <-sessionCtx.Done():
				return
			case job := <-identityJobs:
				var err error
				for {
					jobCtx, jobCancel := context.WithTimeout(sessionCtx, 20*time.Second)
					if job.Type == "cache_cleared" {
						err = s.acceptCacheCleared(jobCtx, session, job)
					} else {
						err = s.confirmIdentity(jobCtx, session, job)
					}
					jobCancel()
					var storageErr identityStorageError
					if !errors.As(err, &storageErr) {
						break
					}
					log.Printf("edge identity SQL retry node=%s type=%s: %v", nodeID, job.Type, err)
					select {
					case <-sessionCtx.Done():
						return
					case <-time.After(time.Second):
					}
				}
				if err != nil {
					select {
					case identityErr <- err:
					case <-sessionCtx.Done():
					}
					return
				}
			}
		}
	}()
	watchdog := time.NewTicker(time.Second)
	defer watchdog.Stop()
	for {
		var message Message
		select {
		case <-sessionCtx.Done():
			return sessionCtx.Err()
		case err := <-writeErr:
			return err
		case err := <-identityErr:
			return err
		case <-watchdog.C:
			s.mu.RLock()
			alive := s.sessionAliveLocked(session, time.Now())
			syncOverdue := (!session.cacheReady || session.pendingRevision > session.appliedRevision) && time.Since(session.syncStarted) > identityIdleTimeout
			s.mu.RUnlock()
			if !alive {
				return errors.New("edge heartbeat timed out")
			}
			if syncOverdue && !s.DatabaseUnavailable() {
				return errors.New("edge configuration acknowledgement timed out")
			}
			continue
		case result := <-received:
			if result.err != nil {
				return result.err
			}
			message = result.message
		}
		if sessionCtx.Err() != nil {
			return sessionCtx.Err()
		}
		if message.NodeID != nodeID {
			return errors.New("message node identity does not match mTLS certificate")
		}
		now := time.Now()
		s.mu.Lock()
		if s.sessions[nodeID] == session {
			session.lastHeartbeat = now
			if len(message.Capabilities) > 0 {
				session.capabilities = append(session.capabilities[:0], message.Capabilities...)
			}
		}
		capabilities := string(session.capabilities)
		if capabilities == "" {
			capabilities = "{}"
		}
		s.mu.Unlock()
		if message.Type == "identity_chunk_ack" || message.Type == "identity_progress" {
			if err := s.acceptIdentityProgress(session, message); err != nil {
				return err
			}
		} else if message.Type == "cache_cleared" || message.Type == "identity_ack" {
			select {
			case identityJobs <- message:
			default:
				log.Printf("edge node=%s redundant identity acknowledgement queue full; awaiting retry", nodeID)
			}
		}
		if len(message.Capabilities) > 0 || lastPersist.IsZero() || now.Sub(lastPersist) >= 30*time.Second {
			select {
			case touchJobs <- capabilities:
			default:
			}
			lastPersist = now
		}
		if message.Type == "heartbeat" {
			ackPayload, _ := json.Marshal(HeartbeatAck{ControllerFault: s.DatabaseFault(), IntervalSeconds: s.HeartbeatInterval(), ServerTime: now, ObservedAddress: observedAddress})
			if err := enqueue(Message{Type: "heartbeat_ack", NodeID: nodeID, Sequence: message.Sequence, Payload: ackPayload, SentAt: now}); err != nil {
				return err
			}
		} else if message.Type == "report" || message.Type == "event_batch" || message.Type == "command_result" {
			select {
			case telemetryJobs <- message:
			default:
				s.deliverCommandResult(CommandResult{CommandID: message.CommandID, Status: "failed", Error: "persistence queue is busy; retry later"})
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
	return s.identitySnapshotForUsers(ctx, nodeID, nil)
}

func (s *ControllerServer) identitySnapshotForUsers(ctx context.Context, nodeID string, requested []int64) (*Message, error) {
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
	revision := time.Now().UnixNano()
	if cache, ok := s.store.(IdentityCacheStore); ok {
		revision, err = cache.NextIdentityRevision(ctx)
		if err != nil {
			return nil, err
		}
	}
	snapshot := IdentitySnapshot{Revision: revision, Incremental: requested != nil}
	requestedSet := map[int64]bool{}
	for _, id := range requested {
		requestedSet[id] = true
	}
	keptUsers := map[int64]bool{}
	accessStore, ok := s.store.(interface {
		CanAccessNode(context.Context, int64, string) (bool, error)
	})
	if !ok {
		return nil, fmt.Errorf("node access store unavailable")
	}
	snapshot.NodeAccessEnforced = true
	var allowedUsers map[int64]bool
	if nodeAccess, ok := s.store.(interface {
		ListNodeUserAccess(context.Context, string) (map[int64]bool, error)
	}); ok {
		allowedUsers, err = nodeAccess.ListNodeUserAccess(ctx, nodeID)
		if err != nil {
			return nil, err
		}
	}
	for _, user := range users {
		if requested != nil && !requestedSet[user.ID] {
			continue
		}
		allowed := allowedUsers[user.ID]
		if allowedUsers == nil {
			allowed, err = accessStore.CanAccessNode(ctx, user.ID, nodeID)
			if err != nil {
				return nil, err
			}
		}
		if !allowed {
			continue
		}
		keptUsers[user.ID] = true
		snapshot.Users = append(snapshot.Users, SnapshotUser{user.ID, user.Username, user.Role, user.Status, user.BanReason})
	}
	for _, id := range requested {
		if !keptUsers[id] {
			snapshot.RemovedUserIDs = append(snapshot.RemovedUserIDs, id)
		}
	}
	keptTokens := map[int64]bool{}
	for _, token := range tokens {
		if !keptUsers[token.UserID] {
			continue
		}
		keptTokens[token.ID] = true
		snapshot.Tokens = append(snapshot.Tokens, SnapshotToken{token.ID, token.UserID, token.Name, token.TokenHash, token.Status, token.BanReason, token.MaxProxyCount, token.ExpiresAt})
	}
	for _, policy := range policies {
		if keptUsers[policy.UserID] {
			snapshot.Policies = append(snapshot.Policies, policy)
		}
	}
	for _, grant := range grants {
		if keptTokens[grant.TokenID] {
			snapshot.Grants = append(snapshot.Grants, grant)
		}
	}
	for _, policy := range dpiPolicies {
		if keptUsers[policy.UserID] {
			snapshot.DPIPolicies = append(snapshot.DPIPolicies, policy)
		}
	}
	if !snapshot.Incremental {
		snapshot.BlockedIPs = blocked
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	return &Message{Type: "identity_snapshot", NodeID: nodeID, Revision: snapshot.Revision, Payload: payload, SentAt: time.Now()}, nil
}

func (s *ControllerServer) dispatchPendingCommands(ctx context.Context, nodeID string) {
	if s.DatabaseUnavailable() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
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
	if sequence < 0 || sequence > (math.MaxInt64-999)/1000 || len(batch.Events) > 100 {
		return nil
	}
	control, ok := s.store.(NodeControlStore)
	if !ok {
		return nil
	}
	acked := make([]string, 0, len(batch.Events))
	for index, event := range batch.Events {
		if event.EventID == "" {
			continue
		}
		if durable, ok := s.store.(interface {
			RecordNodeEventDurably(context.Context, string, int64, string, string, string) error
		}); ok {
			if err := durable.RecordNodeEventDurably(ctx, nodeID, sequence*1000+int64(index), event.EventID, event.EventType, string(event.Payload)); err != nil {
				log.Printf("store edge event %s on %s: %v", event.EventID, nodeID, err)
				continue
			}
			acked = append(acked, event.EventID)
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
