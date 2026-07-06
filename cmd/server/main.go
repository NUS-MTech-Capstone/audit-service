package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/NUS-MTech-Capstone/audit-service/internal/config"
	"github.com/NUS-MTech-Capstone/audit-service/internal/httpapi"
	"github.com/NUS-MTech-Capstone/audit-service/internal/observability"
	"github.com/NUS-MTech-Capstone/audit-service/internal/service"
	"github.com/NUS-MTech-Capstone/audit-service/internal/sessionmanager"
	"github.com/NUS-MTech-Capstone/audit-service/internal/store"
)

func main() {
	observability.ConfigureLogger("audit-service")
	cfg := config.Load()
	st, closeStore, err := store.Open(context.Background(), store.OpenConfig{Driver: cfg.StoreDriver, DatabaseURL: cfg.DatabaseURL})
	if err != nil {
		slog.Error("initialize store failed", "error", err)
		os.Exit(1)
	}
	defer closeStore()

	svc := service.New(st, sessionmanager.New(cfg.SessionManagerURL), cfg.AuditRetention, cfg.AuditMaxBytes)
	addr := ":" + cfg.Port
	slog.Info("server_listening", "addr", addr, "store", cfg.StoreDriver)
	server := &http.Server{
		Addr:              addr,
		Handler:           httpapi.New(svc),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}
