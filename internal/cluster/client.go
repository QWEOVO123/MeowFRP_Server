package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type EdgeClient struct {
	address, nodeID, serverName string
	paths                       TLSFiles
	capabilities                atomic.Value
	connected                   atomic.Bool
	lastError                   atomic.Value
	syncReady                   atomic.Bool
	snapshotHandler             func(context.Context, json.RawMessage) error
	heartbeatProvider           func(context.Context) HeartbeatPayload
	eventProvider               func(context.Context) ([]EventEnvelope, error)
	eventAckHandler             func(context.Context, []string) error
	commandHandler              func(context.Context, NodeCommand) CommandResult
	observedAddressHandler      func(string)
	heartbeatSeconds            atomic.Int64
}

func NewEdgeClient(address, nodeID, serverName string, paths TLSFiles, capabilities any) *EdgeClient {
	client := &EdgeClient{address: NormalizeControllerAddress(address), nodeID: nodeID, serverName: serverName, paths: paths}
	client.SetCapabilities(capabilities)
	client.heartbeatSeconds.Store(5)
	return client
}
func (c *EdgeClient) SetHeartbeatProvider(provider func(context.Context) HeartbeatPayload) {
	c.heartbeatProvider = provider
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
}
func (c *EdgeClient) SetSnapshotHandler(handler func(context.Context, json.RawMessage) error) {
	c.snapshotHandler = handler
}
func (c *EdgeClient) capabilityJSON() json.RawMessage {
	value, _ := c.capabilities.Load().([]byte)
	return append(json.RawMessage(nil), value...)
}
func (c *EdgeClient) Connected() bool   { return c.connected.Load() }
func (c *EdgeClient) SyncReady() bool   { return c.syncReady.Load() }
func (c *EdgeClient) LastError() string { value, _ := c.lastError.Load().(string); return value }
func (c *EdgeClient) Run(ctx context.Context) {
	delay := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		if err := c.connect(ctx); err != nil && !errors.Is(err, context.Canceled) {
			c.lastError.Store(err.Error())
			log.Printf("edge controller connection: %v", err)
		}
		c.connected.Store(false)
		c.syncReady.Store(false)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}
func (c *EdgeClient) connect(ctx context.Context) error {
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
	conn, err := grpc.NewClient(c.address, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)), grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})))
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
		}
	}
	capabilities := c.capabilityJSON()
	if err := enqueue(Message{Type: "hello", NodeID: c.nodeID, Capabilities: capabilities, SentAt: time.Now()}); err != nil {
		return err
	}
	c.connected.Store(true)
	c.lastError.Store("")
	recvErr := make(chan error, 1)
	go func() {
		for {
			var msg Message
			if err := stream.RecvMsg(&msg); err != nil {
				recvErr <- err
				return
			}
			if msg.Type == "identity_snapshot" && c.snapshotHandler != nil {
				if err := c.snapshotHandler(ctx, msg.Payload); err != nil {
					recvErr <- err
					return
				}
				c.syncReady.Store(true)
			} else if msg.Type == "heartbeat_ack" || msg.Type == "welcome" {
				var ack HeartbeatAck
				if json.Unmarshal(msg.Payload, &ack) == nil {
					if ack.IntervalSeconds >= 2 && ack.IntervalSeconds <= 60 {
						c.heartbeatSeconds.Store(int64(ack.IntervalSeconds))
					}
					if ack.ObservedAddress != "" && c.observedAddressHandler != nil {
						c.observedAddressHandler(ack.ObservedAddress)
					}
				}
			} else if msg.Type == "event_ack" {
				var ack EventAck
				if json.Unmarshal(msg.Payload, &ack) == nil && c.eventAckHandler != nil {
					if err := c.eventAckHandler(ctx, ack.EventIDs); err != nil {
						recvErr <- err
						return
					}
				}
			} else if msg.Type == "command" {
				var command NodeCommand
				if json.Unmarshal(msg.Payload, &command) == nil && c.commandHandler != nil {
					result := c.commandHandler(ctx, command)
					payload, _ := json.Marshal(result)
					if err := enqueue(Message{Type: "command_result", NodeID: c.nodeID, CommandID: command.CommandID, Payload: payload, SentAt: time.Now()}); err != nil {
						recvErr <- err
						return
					}
				}
			}
		}
	}()
	// Announce current presence immediately after the stream is established;
	// subsequent heartbeats use the interval selected by the controller.
	timer := time.NewTimer(10 * time.Millisecond)
	defer timer.Stop()
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
		case <-timer.C:
			seq++
			capabilities = c.capabilityJSON()
			heartbeat := HeartbeatPayload{}
			if c.heartbeatProvider != nil {
				heartbeat = c.heartbeatProvider(ctx)
			}
			payload, _ := json.Marshal(heartbeat)
			if err := enqueue(Message{Type: "heartbeat", NodeID: c.nodeID, Sequence: seq, Capabilities: capabilities, Payload: payload, SentAt: time.Now()}); err != nil {
				return err
			}
			if c.eventProvider != nil {
				if events, eventErr := c.eventProvider(ctx); eventErr == nil && len(events) > 0 {
					batchPayload, _ := json.Marshal(EventBatch{Events: events})
					if err := enqueue(Message{Type: "event_batch", NodeID: c.nodeID, Sequence: seq, Payload: batchPayload, SentAt: time.Now()}); err != nil {
						return err
					}
				}
			}
			timer.Reset(time.Duration(c.heartbeatSeconds.Load()) * time.Second)
		}
	}
}
