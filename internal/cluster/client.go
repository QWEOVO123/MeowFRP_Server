package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type EdgeClient struct {
	controllerFault             atomic.Bool
	faultGeneration             atomic.Uint64
	faultHandler                func(bool)
	address, nodeID, serverName string
	paths                       TLSFiles
	capabilities                atomic.Value
	connected                   atomic.Bool
	lastError                   atomic.Value
	syncReady                   atomic.Bool
	snapshotHandler             func(context.Context, json.RawMessage) error
	cacheResetHandler           func(context.Context) error
	heartbeatProvider           func(context.Context) HeartbeatPayload
	eventProvider               func(context.Context) ([]EventEnvelope, error)
	eventAckHandler             func(context.Context, []string) error
	commandHandler              func(context.Context, NodeCommand) CommandResult
	observedAddressHandler      func(string)
	heartbeatSeconds            atomic.Int64
	capabilityChanged           chan struct{}
	sessionCache                tls.ClientSessionCache
	bootID                      string
}

func NewEdgeClient(address, nodeID, serverName string, paths TLSFiles, capabilities any) *EdgeClient {
	client := &EdgeClient{address: NormalizeControllerAddress(address), nodeID: nodeID, serverName: serverName, paths: paths, capabilityChanged: make(chan struct{}, 1), bootID: fmt.Sprintf("boot-%d-%d", os.Getpid(), time.Now().UnixNano())}
	client.SetCapabilities(capabilities)
	client.heartbeatSeconds.Store(5)
	return client
}
func (c *EdgeClient) SetHeartbeatProvider(provider func(context.Context) HeartbeatPayload) {
	c.heartbeatProvider = provider
}

// EnableSessionResumption is a boot preference. Never skips certificate or
// node identity validation; the cache lives only within this process.
func (c *EdgeClient) EnableSessionResumption(enabled bool) {
	if enabled {
		c.sessionCache = tls.NewLRUClientSessionCache(32)
	} else {
		c.sessionCache = nil
	}
}
func (c *EdgeClient) SetEventProvider(provider func(context.Context) ([]EventEnvelope, error)) {
	c.eventProvider = provider
}
func (c *EdgeClient) SetEventAckHandler(handler func(context.Context, []string) error) {
	c.eventAckHandler = handler
}
func (c *EdgeClient) SetCommandHandler(handler func(context.Context, NodeCommand) CommandResult) {
	c.commandHandler = handler
}
func (c *EdgeClient) SetObservedAddressHandler(handler func(string)) {
	c.observedAddressHandler = handler
}
func (c *EdgeClient) SetCapabilities(value any) {
	encoded, _ := json.Marshal(value)
	c.capabilities.Store(encoded)
	select {
	case c.capabilityChanged <- struct{}{}:
	default:
	}
}
func (c *EdgeClient) SetSnapshotHandler(handler func(context.Context, json.RawMessage) error) {
	c.snapshotHandler = handler
}
func (c *EdgeClient) SetCacheResetHandler(handler func(context.Context) error) {
	c.cacheResetHandler = handler
}
func (c *EdgeClient) capabilityJSON() json.RawMessage {
	value, _ := c.capabilities.Load().([]byte)
	return append(json.RawMessage(nil), value...)
}
func (c *EdgeClient) Connected() bool                    { return c.connected.Load() }
func (c *EdgeClient) ControllerFault() bool              { return c.controllerFault.Load() }
func (c *EdgeClient) FaultGeneration() uint64            { return c.faultGeneration.Load() }
func (c *EdgeClient) SetFaultHandler(handler func(bool)) { c.faultHandler = handler }
func (c *EdgeClient) signalFault() {
	c.faultGeneration.Add(1)
	if c.faultHandler != nil {
		c.faultHandler(true)
	}
}
func (c *EdgeClient) SyncReady() bool   { return c.syncReady.Load() }
func (c *EdgeClient) LastError() string { value, _ := c.lastError.Load().(string); return value }
func (c *EdgeClient) Run(ctx context.Context) {
	delay := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		// The previous connect has joined its apply worker before we clear SQLite.
		// A failed clear must never be reported as successful or followed by hello.
		var err error
		if c.cacheResetHandler != nil {
			resetCtx, resetCancel := context.WithTimeout(ctx, identityIdleTimeout)
			err = c.cacheResetHandler(resetCtx)
			resetCancel()
		}
		if err == nil {
			err = c.connect(ctx)
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			c.lastError.Store(err.Error())
			log.Printf("edge controller connection: %v", err)
		}
		wasConnected := c.connected.Load()
		c.signalFault()
		c.connected.Store(false)
		c.syncReady.Store(false)
		if c.cacheResetHandler != nil && ctx.Err() == nil {
			resetCtx, resetCancel := context.WithTimeout(ctx, identityIdleTimeout)
			if err := c.cacheResetHandler(resetCtx); err != nil {
				c.lastError.Store("discard disconnected identity cache: " + err.Error())
				log.Printf("edge cache discard after disconnect failed: %v", err)
			}
			resetCancel()
		}
		delay = nextReconnectDelay(delay, wasConnected)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func nextReconnectDelay(current time.Duration, connectionEstablished bool) time.Duration {
	if connectionEstablished {
		return time.Second
	}
	current *= 2
	if current > 30*time.Second {
		return 30 * time.Second
	}
	return current
}
func (c *EdgeClient) connect(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	caPEM, certPEM, keyPEM := c.paths.CAPEM, c.paths.CertPEM, c.paths.KeyPEM
	if len(caPEM) == 0 {
		var err error
		caPEM, err = os.ReadFile(c.paths.CAFile)
		if err != nil {
			return err
		}
	}
	if len(certPEM) == 0 {
		var err error
		certPEM, err = os.ReadFile(c.paths.CertFile)
		if err != nil {
			return err
		}
	}
	if len(keyPEM) == 0 {
		var err error
		keyPEM, err = os.ReadFile(c.paths.KeyFile)
		if err != nil {
			return err
		}
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("invalid controller CA")
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: c.serverName, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}
	tlsCfg.ClientSessionCache = c.sessionCache
	conn, err := grpc.NewClient(c.address, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)), grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{}), grpc.MaxCallRecvMsgSize(maxControlMessageBytes), grpc.MaxCallSendMsgSize(maxControlMessageBytes)))
	if err != nil {
		return err
	}
	defer conn.Close()
	desc := &controlServiceDesc.Streams[0]
	stream, err := conn.NewStream(ctx, desc, controlMethod)
	if err != nil {
		return err
	}
	send := make(chan Message, 128)
	sendErr := make(chan error, 1)
	go func() {
		for {
			select {
			case message := <-send:
				if err := stream.SendMsg(&message); err != nil {
					sendErr <- err
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	enqueue := func(message Message) error {
		select {
		case send <- message:
			return nil
		case err := <-sendErr:
			return err
		case <-ctx.Done():
			return ctx.Err()
		default:
			return errors.New("edge control send queue is full")
		}
	}
	capabilities := c.capabilityJSON()
	protocol := 2
	if c.cacheResetHandler != nil {
		protocol = 3
	}
	log.Printf("edge startup hello node=%s boot=%s cache_protocol=%d", c.nodeID, c.bootID, protocol)
	if err := enqueue(Message{Type: "hello", NodeID: c.nodeID, BootID: c.bootID, CacheProtocol: protocol, AdmissionProtocol: 1, Capabilities: capabilities, SentAt: time.Now()}); err != nil {
		return err
	}
	var lastReceived atomic.Int64
	lastReceived.Store(time.Now().UnixNano())
	recvErr := make(chan error, 1)
	var locallyAppliedRevision atomic.Int64
	applyJobs := make(chan Message, 1)
	applyDone := make(chan struct{})
	recvDone := make(chan struct{})
	fail := func(err error) {
		select {
		case recvErr <- err:
		default:
		}
	}
	go func() {
		defer close(applyDone)
		for {
			select {
			case <-ctx.Done():
				return
			case job := <-applyJobs:
				if ctx.Err() != nil {
					return
				}
				if job.Type == "cache_reset" {
					if c.cacheResetHandler == nil {
						fail(errors.New("cache reset handler unavailable"))
						return
					}
					if err := c.cacheResetHandler(ctx); err != nil {
						fail(err)
						return
					}
					locallyAppliedRevision.Store(0)
					log.Printf("edge cache cleared node=%s session=%s; reporting committed reset", c.nodeID, job.CacheSessionID)
					if err := enqueue(Message{Type: "cache_cleared", NodeID: c.nodeID, CacheSessionID: job.CacheSessionID, SentAt: time.Now()}); err != nil {
						fail(err)
						return
					}
					continue
				}
				if c.snapshotHandler == nil {
					fail(errors.New("identity apply handler unavailable"))
					return
				}
				var header struct {
					Revision int64 `json:"revision"`
				}
				if err := json.Unmarshal(job.Payload, &header); err != nil || header.Revision != job.Revision {
					fail(errors.New("identity payload revision mismatch"))
					return
				}
				var progressSequence int64
				applyCtx := WithIdentityProgress(ctx, func(completed int64) {
					if job.CacheProtocol < 3 {
						return
					}
					progressSequence++
					if err := enqueue(Message{Type: "identity_progress", NodeID: c.nodeID, CacheSessionID: job.CacheSessionID, Revision: job.Revision, Sequence: progressSequence, SentAt: time.Now()}); err != nil {
						fail(err)
					}
				})
				if err := c.snapshotHandler(applyCtx, job.Payload); err != nil {
					fail(fmt.Errorf("apply identity revision %d: %w", job.Revision, err))
					return
				}
				locallyAppliedRevision.Store(job.Revision)
				if job.CacheProtocol < 2 {
					c.syncReady.Store(true)
				}
				log.Printf("identity locally applied node=%s revision=%d; sending ACK", c.nodeID, job.Revision)
				if err := enqueue(Message{Type: "identity_ack", NodeID: c.nodeID, Revision: job.Revision, CacheSessionID: job.CacheSessionID, SentAt: time.Now()}); err != nil {
					fail(err)
					return
				}
			}
		}
	}()
	auxJobs := make(chan Message, 128)
	auxDone := make(chan struct{})
	handleAux := func(msg Message) {
		if msg.Type == "event_ack" {
			var ack EventAck
			if json.Unmarshal(msg.Payload, &ack) == nil && c.eventAckHandler != nil {
				if err := c.eventAckHandler(ctx, ack.EventIDs); err != nil {
					fail(err)
					return
				}
			}
		} else if msg.Type == "command" {
			var command NodeCommand
			if json.Unmarshal(msg.Payload, &command) == nil && command.Command == "request_report" {
				report := HeartbeatPayload{}
				if c.heartbeatProvider != nil {
					report = c.heartbeatProvider(ctx)
				}
				if c.eventProvider != nil {
					events, err := c.eventProvider(ctx)
					if err != nil {
						report.ReportError = "read edge events: " + err.Error()
					}
					if err == nil && len(events) > 0 {
						payload, _ := json.Marshal(EventBatch{Events: events})
						if err := enqueue(Message{Type: "event_batch", NodeID: c.nodeID, Sequence: time.Now().UnixMicro(), Payload: payload}); err != nil {
							fail(err)
							return
						}
					}
				}
				payload, _ := json.Marshal(report)
				if err := enqueue(Message{Type: "report", NodeID: c.nodeID, CommandID: command.CommandID, Capabilities: c.capabilityJSON(), Payload: payload, SentAt: time.Now()}); err != nil {
					fail(err)
					return
				}
				return
			}
			if json.Unmarshal(msg.Payload, &command) == nil && c.commandHandler != nil {
				result := c.commandHandler(ctx, command)
				payload, _ := json.Marshal(result)
				if err := enqueue(Message{Type: "command_result", NodeID: c.nodeID, CommandID: command.CommandID, Capabilities: c.capabilityJSON(), Payload: payload, SentAt: time.Now()}); err != nil {
					fail(err)
					return
				}
			}
		}
	}
	go func() {
		defer close(auxDone)
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-auxJobs:
				if ctx.Err() != nil {
					return
				}
				handleAux(msg)
			}
		}
	}()
	defer func() {
		// Fence new logins immediately, before waiting for disk/command workers.
		// Only cache deletion waits for them, so they cannot restore stale data.
		c.connected.Store(false)
		c.syncReady.Store(false)
		c.signalFault()
		cancel()
		_ = conn.Close()
		<-applyDone
		<-recvDone
		<-auxDone
	}()
	queueApply := func(job Message) error {
		select {
		case applyJobs <- job:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
			return errors.New("overlapping identity application")
		}
	}
	go func() {
		defer close(recvDone)
		identityProtocol := 0
		cacheSessionID := ""
		var chunkBuffer []byte
		var chunkRevision int64
		var chunkIndex, chunkTotal int
		for {
			var msg Message
			if err := stream.RecvMsg(&msg); err != nil {
				fail(err)
				return
			}
			if ctx.Err() != nil {
				return
			}
			lastReceived.Store(time.Now().UnixNano())
			if msg.NodeID != "" && msg.NodeID != c.nodeID {
				fail(errors.New("controller message node mismatch"))
				return
			}
			if msg.Type == "identity_chunk" {
				if identityProtocol < 3 || msg.CacheSessionID != cacheSessionID {
					fail(errors.New("identity chunk session mismatch"))
					return
				}
				var chunk IdentityChunk
				if err := json.Unmarshal(msg.Payload, &chunk); err != nil {
					fail(err)
					return
				}
				if chunk.Index == 0 {
					if len(chunkBuffer) > 0 {
						fail(errors.New("overlapping identity fragments"))
						return
					}
					chunkRevision, chunkTotal, chunkIndex = msg.Revision, chunk.Total, 0
					c.syncReady.Store(false)
				}
				if chunk.Total < 1 || chunk.Total != chunkTotal || chunk.Index != chunkIndex || msg.Sequence != int64(chunkIndex) || msg.Revision != chunkRevision || len(chunk.Data) == 0 || len(chunk.Data) > identityChunkBytes {
					fail(errors.New("invalid identity fragment sequence"))
					return
				}
				chunkBuffer = append(chunkBuffer, chunk.Data...)
				if err := enqueue(Message{Type: "identity_chunk_ack", NodeID: c.nodeID, CacheSessionID: cacheSessionID, Revision: msg.Revision, Sequence: int64(chunkIndex), SentAt: time.Now()}); err != nil {
					fail(err)
					return
				}
				chunkIndex++
				if chunkIndex == chunkTotal {
					job := Message{Type: "identity_snapshot", CacheProtocol: identityProtocol, CacheSessionID: cacheSessionID, Revision: msg.Revision, Payload: chunkBuffer}
					chunkBuffer = nil
					if err := queueApply(job); err != nil {
						fail(err)
						return
					}
				}
			} else if msg.Type == "identity_snapshot" && c.snapshotHandler != nil {
				if identityProtocol >= 2 && (msg.CacheSessionID == "" || msg.CacheSessionID != cacheSessionID) {
					fail(errors.New("identity snapshot cache session mismatch"))
					return
				}
				c.syncReady.Store(false)
				msg.CacheProtocol = identityProtocol
				msg.CacheSessionID = cacheSessionID
				if err := queueApply(msg); err != nil {
					fail(err)
					return
				}
			} else if msg.Type == "identity_confirmed" {
				if msg.CacheSessionID != cacheSessionID || msg.Revision != locallyAppliedRevision.Load() {
					fail(errors.New("controller identity confirmation mismatch"))
					return
				}
				c.syncReady.Store(identityProtocol < 3 || msg.SyncComplete)
				if c.syncReady.Load() && !c.controllerFault.Load() && c.faultHandler != nil {
					c.faultHandler(false)
				}
				log.Printf("identity synchronization confirmed node=%s revision=%d sync_complete=%t", c.nodeID, msg.Revision, c.syncReady.Load())
			} else if msg.Type == "heartbeat_ack" || msg.Type == "welcome" || msg.Type == "controller_state" {
				c.connected.Store(true)
				c.lastError.Store("")
				var ack HeartbeatAck
				if json.Unmarshal(msg.Payload, &ack) == nil {
					wasFault := c.controllerFault.Swap(ack.ControllerFault)
					if ack.ControllerFault && !wasFault {
						c.signalFault()
						c.syncReady.Store(false)
					}
					if msg.Type == "welcome" {
						c.signalFault()
						identityProtocol = ack.IdentityProtocol
						cacheSessionID = msg.CacheSessionID
						if identityProtocol >= 3 {
							c.syncReady.Store(false)
							chunkBuffer = nil
							if cacheSessionID == "" {
								fail(errors.New("missing cache reset epoch"))
								return
							}
							if err := queueApply(Message{Type: "cache_reset", CacheSessionID: cacheSessionID}); err != nil {
								fail(err)
								return
							}
						}
					}
					if ack.IntervalSeconds >= 2 && ack.IntervalSeconds <= 60 {
						c.heartbeatSeconds.Store(int64(ack.IntervalSeconds))
					}
					if ack.ObservedAddress != "" && c.observedAddressHandler != nil {
						c.observedAddressHandler(ack.ObservedAddress)
					}
				}
			} else if msg.Type == "event_ack" || msg.Type == "command" {
				select {
				case auxJobs <- msg:
				case <-ctx.Done():
					return
				default:
					fail(errors.New("edge auxiliary control queue full"))
					return
				}
			}
		}
	}()
	// Heartbeats carry no telemetry or policy snapshots; reporting is on demand.
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
	watchdog := time.NewTicker(time.Second)
	defer watchdog.Stop()
	var seq int64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-recvErr:
			if errors.Is(err, io.EOF) {
				return errors.New("controller closed the stream")
			}
			return err
		case err := <-sendErr:
			return err
		case <-watchdog.C:
			if time.Since(time.Unix(0, lastReceived.Load())) > heartbeatTimeout(c.heartbeatSeconds.Load()) {
				return errors.New("controller heartbeat response timed out")
			}
		case <-c.capabilityChanged:
			if err := enqueue(Message{Type: "capabilities_update", NodeID: c.nodeID, Capabilities: c.capabilityJSON(), SentAt: time.Now()}); err != nil {
				return err
			}
		case <-timer.C:
			seq++
			if err := enqueue(Message{Type: "heartbeat", NodeID: c.nodeID, Sequence: seq, SentAt: time.Now()}); err != nil {
				return err
			}
			timer.Reset(time.Duration(c.heartbeatSeconds.Load()) * time.Second)
		}
	}
}
