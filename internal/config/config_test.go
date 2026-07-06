package config

import (
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	t.Setenv("PORT", "9090")
	t.Setenv("STORE_DRIVER", "postgres")
	t.Setenv("DATABASE_URL", "postgres://db")
	t.Setenv("SESSION_MANAGER_URL", "http://session-manager:8081")
	t.Setenv("SESSION_AUDIT_RETENTION_SECONDS", "86400")
	t.Setenv("SESSION_AUDIT_MAX_BYTES_PER_SESSION", "4096")

	cfg := Load()
	if cfg.Port != "9090" || cfg.StoreDriver != "postgres" || cfg.DatabaseURL != "postgres://db" || cfg.SessionManagerURL != "http://session-manager:8081" {
		t.Fatalf("config = %#v", cfg)
	}
	if cfg.AuditRetention != 24*time.Hour || cfg.AuditMaxBytes != 4096 {
		t.Fatalf("audit config = %#v", cfg)
	}
}

func TestLoadConfigDefaultsInvalidValues(t *testing.T) {
	t.Setenv("SESSION_AUDIT_RETENTION_SECONDS", "bad")
	t.Setenv("SESSION_AUDIT_MAX_BYTES_PER_SESSION", "bad")

	cfg := Load()
	if cfg.Port != "8085" || cfg.StoreDriver != "memory" || cfg.SessionManagerURL != "http://localhost:8081" {
		t.Fatalf("defaults = %#v", cfg)
	}
	if cfg.AuditRetention != 7*24*time.Hour || cfg.AuditMaxBytes != 16*1024*1024 {
		t.Fatalf("audit defaults = %#v", cfg)
	}
}
