package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shutcode/openvpn-admin/api"
	"github.com/shutcode/openvpn-admin/internal/config"
	"github.com/shutcode/openvpn-admin/internal/ovpn"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] != "serve" {
		fmt.Fprintf(os.Stderr, "usage: %s [serve]\n", os.Args[0])
		os.Exit(2)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	mgr := ovpn.NewManager(
		cfg.OpenVPNPath,
		cfg.EasyRSAPath,
		cfg.ClientsDir,
		cfg.StatusFile,
		cfg.ServiceUnit,
	)
	mgr.ListenPort = cfg.OpenVPNListenPort
	mgr.ListenProto = cfg.OpenVPNListenProto

	app := api.NewServer(nil, nil, api.ServerConfig{
		JWTSecret:      cfg.JWTSecret,
		AllowedOrigins: nil,
		RequireAuth:    true,
		DashboardDir:   cfg.DashboardDir,
		Manager:        mgr,
		AdminUser:      cfg.AdminUser,
		AdminPassword:  cfg.AdminPassword,
	})

	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("OpenVPN Admin listening on %s", server.Addr)
		errCh <- server.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Printf("received %s, shutting down", sig)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server failed: %v", err)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
		_ = server.Close()
	}
}
