package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatedier/frp/pkg/dpihook"

	"frp-control-server/internal/config"
	"frp-control-server/internal/db"
	"frp-control-server/internal/dpi"
	"frp-control-server/internal/dpiengine"
	"frp-control-server/internal/frpcore"
	"frp-control-server/internal/httpapi"
)

func main() {
	port := flag.Int("port", 0, "API listen port, for example -port=18080")
	flag.Parse()
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if *port > 0 {
		cfg.HTTPAddr = fmt.Sprintf(":%d", *port)
	}

	var store *db.Store
	if cfg.MySQLDSN != "" {
		store, err = db.Open(cfg.MySQLDSN)
		if err != nil {
			log.Printf("mysql is not ready, setup api will stay available: %v", err)
		} else if err := store.Migrate(context.Background()); err != nil {
			log.Printf("mysql migration failed, setup api will stay available: %v", err)
			_ = store.Close()
			store = nil
		}
	}
	if store == nil {
		log.Printf("running in setup mode; config path: %s", cfg.ConfigPath)
	} else {
		defer store.Close()
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
	frpCore := frpcore.NewManager(dpiService)
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
	api := httpapi.NewServer(cfg, store, httpapi.WithDPIService(dpiService), httpapi.WithFRPCore(frpCore))
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

	if err := frpCore.StartEmbeddedFRPS(rootCtx, cfg); err != nil {
		log.Fatalf("embedded frps: %v", err)
	}
	if cfg.EmbeddedFRPEnabled {
		log.Printf("embedded frps listening on %s:%d", cfg.FRPBindAddr, cfg.FRPServerPort)
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
