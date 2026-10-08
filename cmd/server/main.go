package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/fatedier/frp/pkg/dpihook"

	"frp-control-server/internal/cluster"
	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
	"frp-control-server/internal/dpi"
	"frp-control-server/internal/dpiengine"
	"frp-control-server/internal/edgestate"
	"frp-control-server/internal/frpcore"
	"frp-control-server/internal/httpapi"
)

func main() {
	apiPort := flag.Int("APIport", 0, "API listen port, for example -APIport=18080")
	legacyPort := flag.Int("port", 0, "deprecated alias for -APIport")
	apiBind := flag.String("APIbind", "", "API bind address, for example -APIbind=127.0.0.1")
	flag.Parse()
	port := *apiPort
	if port == 0 {
		port = *legacyPort
	}
	if port < 0 || port > 65535 {
		log.Fatalf("invalid API port %d", port)
	}
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if port > 0 || *apiBind != "" {
		host := *apiBind
		if host == "" {
			host = httpBindHost(cfg.HTTPAddr)
		}
		if port == 0 {
			port = httpBindPort(cfg.HTTPAddr, 8080)
		}
		cfg.HTTPAddr = fmt.Sprintf("%s:%d", host, port)
	}
	if cfg.ConfigState == "unconfigured" || cfg.ConfigState == "invalid" {
		setupPort := 8080
		if port > 0 {
			setupPort = port
		}
		setupHost := httpBindHost(cfg.HTTPAddr)
		if *apiBind != "" {
			setupHost = *apiBind
		}
		cfg.HTTPAddr = fmt.Sprintf("%s:%d", setupHost, setupPort)
		// Setup mode gates listener startup below. Do not change the persisted
		// preference: setup handlers save this Config after initialization.
		if cfg.ConfigError != "" {
			log.Printf("configuration is invalid; entering local setup mode: %s", cfg.ConfigError)
		}
	}
	log.Printf("startup config: path=%s state=%s mode=%s configuration_mode=%s embedded_frps_enabled=%t edge_access_enabled=%t", cfg.ConfigPath, cfg.ConfigState, cfg.Mode, cfg.ConfigurationMode, cfg.EmbeddedFRPEnabled, cfg.Controller.EdgeAccessEnabled)

	var store *db.Store
	if cfg.Mode == config.ModeController && cfg.MySQLDSN != "" {
		store, err = db.Open(cfg.MySQLDSN)
		if err != nil {
			log.Printf("mysql is not ready, setup api will stay available: %v", err)
		} else if err := store.Migrate(context.Background()); err != nil {
			log.Printf("mysql migration failed, setup api will stay available: %v", err)
			_ = store.Close()
			store = nil
		}
	}
	if store == nil && cfg.Mode == config.ModeController {
		log.Printf("running in setup mode; config path: %s", cfg.ConfigPath)
	} else if store != nil {
		defer store.Close()
	}
	var edgeState *edgestate.Store
	var edgeClient *cluster.EdgeClient
	if cfg.Mode == config.ModeEdge && cfg.ConfigState == "configured" {
		edgeState, err = edgestate.Open(config.ResolvePath(cfg.ConfigPath, cfg.Edge.StatePath))
		if err != nil {
			log.Fatalf("open edge state: %v", err)
		}
		defer edgeState.Close()
		resetCtx, resetCancel := context.WithTimeout(context.Background(), 15*time.Second)
		err = edgeState.ResetIdentityCache(resetCtx)
		resetCancel()
		if err != nil {
			log.Fatalf("reset edge identity cache at boot: %v", err)
		}
		edgeTLS := cluster.TLSFiles{CAFile: config.ResolvePath(cfg.ConfigPath, cfg.Edge.TLS.CAFile), CertFile: config.ResolvePath(cfg.ConfigPath, cfg.Edge.TLS.CertFile), KeyFile: config.ResolvePath(cfg.ConfigPath, cfg.Edge.TLS.KeyFile)}
		if cfg.Edge.TLS.CACertificateBase64 != "" {
			edgeTLS.CAPEM, err = config.DecodePEM(cfg.Edge.TLS.CACertificateBase64)
			if err != nil {
				log.Fatalf("decode edge CA: %v", err)
			}
			edgeTLS.CertPEM, err = config.DecodePEM(cfg.Edge.TLS.CertificateBase64)
			if err != nil {
				log.Fatalf("decode edge certificate: %v", err)
			}
			edgeTLS.KeyPEM, err = config.DecodePEM(cfg.Edge.TLS.PrivateKeyBase64)
			if err != nil {
				log.Fatalf("decode edge private key: %v", err)
			}
		}
		edgeClient = cluster.NewEdgeClient(cfg.Edge.ControllerAddr, cfg.Edge.NodeID, cfg.Edge.ServerName, edgeTLS, map[string]any{"reporting": cfg.Edge.Reporting, "remote_commands": cfg.Edge.RemoteCommands, "controller_administration_enabled": cfg.Edge.ControllerAdministrationEnabled, "admin_username": cfg.InitialAdmin.Username, "admin_display_name": cfg.InitialAdmin.DisplayName, "runtime_settings": cfg.Node})
		edgeClient.SetSnapshotHandler(edgeState.ApplyIdentitySnapshot)
		edgeClient.SetCacheResetHandler(edgeState.DiscardControlIdentityCache)
		edgeClient.EnableSessionResumption(cfg.ConnectionTuning.EnableMTLSSessionResumption)
	}
	var dpiEventSink dpi.EventSink
	if store != nil {
		dpiEventSink = store
	}
	var dpiPolicyProvider dpi.PolicyProvider
	if store != nil {
		dpiPolicyProvider = store
	}
	dpiService := dpi.NewService(dpi.Options{
		Engine:         dpiengine.NewCompositeEngine(),
		PolicyProvider: dpiPolicyProvider,
		EventSink:      dpiEventSink,
	})
	if edgeState != nil {
		dpiService.SetPolicyProvider(edgeState)
		dpiService.SetEventSink(edgeState)
	}
	frpCore := frpcore.NewManager(dpiService)
	frpCore.SetUDPFlowTimeout(cfg.UDPConnectionTTL)
	if store != nil {
		if blocks, err := store.ListBlockedInboundIPs(context.Background()); err == nil {
			for _, block := range blocks {
				frpCore.SetBlockedInboundIP(frpcore.BlockedInboundIP{
					IP:        block.IP,
					Reason:    block.Reason,
					CreatedAt: block.CreatedAt,
				})
			}
		} else {
			log.Printf("load blocked inbound ips failed: %v", err)
		}
	}
	dpihook.Register(frpCore)
	var controllerControl *cluster.ControllerServer
	if cfg.ConfigState == "configured" && cfg.Mode == config.ModeController && cfg.Controller.EdgeAccessEnabled && store != nil {
		controllerControl, err = buildControllerControl(cfg, store)
		if err != nil {
			log.Fatalf("controller PKI: %v", err)
		}
		controllerControl.SetHeartbeatInterval(cfg.Controller.HeartbeatIntervalSeconds)
		controllerControl.ConfigureTransport(time.Duration(cfg.ConnectionTuning.MTLSHandshakeTimeoutSeconds)*time.Second, cfg.ConnectionTuning.DisableMTLSSessionTickets)
	}
	api := httpapi.NewServer(cfg, store, httpapi.WithDPIService(dpiService), httpapi.WithFRPCore(frpCore), httpapi.WithEdgeRuntime(edgeState, edgeClient), httpapi.WithControllerControl(controllerControl))
	if edgeState != nil {
		log.SetOutput(io.MultiWriter(os.Stderr, edgestate.NewRuntimeLogWriter(edgeState, api.EdgeRuntimeLogsEnabled)))
	}
	if edgeClient != nil {
		edgeClient.SetSnapshotHandler(func(ctx context.Context, payload json.RawMessage) error {
			var snapshot cluster.IdentitySnapshot
			if err := json.Unmarshal(payload, &snapshot); err != nil {
				return err
			}
			if err := edgeState.ApplyIdentitySnapshot(ctx, payload); err != nil {
				return err
			}
			// Never revoke all runtime leases because a later baseline page has
			// not arrived yet. Finalization performs a complete permission check.
			if snapshot.Baseline && !snapshot.BaselineEnd {
				return nil
			}
			affected := map[int64]bool{}
			for _, user := range snapshot.Users {
				affected[user.ID] = true
			}
			for _, id := range snapshot.RemovedUserIDs {
				affected[id] = true
			}
			checkedLeases := map[string]bool{}
			lastProgress := time.Now()
			for _, connection := range frpCore.ListConnections(cfg.UDPConnectionTTL) {
				if frpCore.ClientDraining(connection.TokenID, connection.ClientID) {
					continue
				}
				if snapshot.Incremental && !affected[connection.UserID] {
					continue
				}
				if checkedLeases[connection.LeaseID] {
					continue
				}
				checkedLeases[connection.LeaseID] = true
				if err := edgeState.RuntimeConnectionAuthorized(ctx, connection.UserID, connection.TokenID, connection.LeaseID); err != nil {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					frpCore.TerminateConnectionsForLease(connection.LeaseID)
				}
				if len(checkedLeases)%64 == 0 || time.Since(lastProgress) >= time.Second {
					cluster.ReportIdentityProgress(ctx, int64(len(checkedLeases)))
					lastProgress = time.Now()
				}
			}
			blocks, err := edgeState.ListBlockedIPs(ctx)
			if err != nil {
				return err
			}
			wanted := map[string]bool{}
			for _, block := range blocks {
				wanted[block.IP] = true
				frpCore.EnforceBlockedInboundIP(frpcore.BlockedInboundIP{IP: block.IP, Reason: block.Reason, CreatedAt: block.CreatedAt})
			}
			for _, block := range frpCore.ListBlockedInboundIPs() {
				if !wanted[block.IP] {
					frpCore.UnblockInboundIP(block.IP)
				}
			}
			return nil
		})
		edgeClient.SetHeartbeatProvider(api.EdgeHeartbeatPayload)
		edgeClient.SetEventProvider(api.EdgePendingEvents)
		edgeClient.SetEventAckHandler(edgeState.AcknowledgeEvents)
		edgeClient.SetCommandHandler(api.HandleEdgeCommand)
		edgeClient.SetObservedAddressHandler(api.HandleObservedAddress)
		if blocks, blockErr := edgeState.ListBlockedIPs(context.Background()); blockErr == nil {
			for _, block := range blocks {
				frpCore.SetBlockedInboundIP(frpcore.BlockedInboundIP{IP: block.IP, Reason: block.Reason, CreatedAt: block.CreatedAt})
			}
		}
		go edgeClient.Run(rootCtx)
	}
	api.StartClientHeartbeatWatchdog(rootCtx)
	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           api.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		log.Printf("frp control server listening on %s", cfg.HTTPAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()
	if controllerControl != nil {
		if err := controllerControl.Start(rootCtx, cfg.Controller.ListenAddr); err != nil {
			log.Fatalf("controller node endpoint: %v", err)
		}
		log.Printf("controller mTLS endpoint listening on %s", cfg.Controller.ListenAddr)
	}

	if cfg.ConfigState == "configured" {
		if err := frpCore.StartEmbeddedFRPS(rootCtx, cfg); err != nil {
			log.Fatalf("embedded frps: %v", err)
		}
	}
	if cfg.ConfigState != "configured" {
		log.Printf("embedded frps not started: initialization or configuration repair requires a restart")
	} else if cfg.EmbeddedFRPEnabled {
		log.Printf("embedded frps listening on %s:%d", cfg.FRPBindAddr, cfg.FRPServerPort)
	} else {
		log.Printf("embedded frps disabled by configuration; no FRP control port will be opened by this process")
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	_ = frpCore.Close()
	rootCancel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func httpBindHost(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	return ""
}

func httpBindPort(addr string, fallback int) int {
	_, rawPort, err := net.SplitHostPort(addr)
	if err != nil {
		return fallback
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port <= 0 || port > 65535 {
		return fallback
	}
	return port
}

func buildControllerControl(cfg config.Config, store *db.Store) (*cluster.ControllerServer, error) {
	if cfg.Controller.TLS.CACertificateBase64 != "" {
		var m cluster.PKIMaterial
		var err error
		m.CACertificate, err = config.DecodePEM(cfg.Controller.TLS.CACertificateBase64)
		if err != nil {
			return nil, err
		}
		m.CAPrivateKey, err = config.DecodePEM(cfg.Controller.TLS.CAPrivateKeyBase64)
		if err != nil {
			return nil, err
		}
		m.Certificate, err = config.DecodePEM(cfg.Controller.TLS.CertificateBase64)
		if err != nil {
			return nil, err
		}
		m.PrivateKey, err = config.DecodePEM(cfg.Controller.TLS.PrivateKeyBase64)
		if err != nil {
			return nil, err
		}
		return cluster.NewControllerServerWithMaterial(store, m), nil
	}
	paths := cluster.DefaultPKIPaths(cfg.ConfigPath)
	if cfg.Controller.TLS.CAFile != "" {
		paths.CAFile = config.ResolvePath(cfg.ConfigPath, cfg.Controller.TLS.CAFile)
	}
	if cfg.Controller.CAKeyFile != "" {
		paths.CAKeyFile = config.ResolvePath(cfg.ConfigPath, cfg.Controller.CAKeyFile)
	}
	if cfg.Controller.TLS.CertFile != "" {
		paths.CertFile = config.ResolvePath(cfg.ConfigPath, cfg.Controller.TLS.CertFile)
	}
	if cfg.Controller.TLS.KeyFile != "" {
		paths.KeyFile = config.ResolvePath(cfg.ConfigPath, cfg.Controller.TLS.KeyFile)
	}
	if err := cluster.EnsureControllerPKI(paths, cfg.Controller.PublicAddress); err != nil {
		return nil, err
	}
	return cluster.NewControllerServer(store, paths), nil
}
