package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port              string
	StoreDriver       string
	DatabaseURL       string
	SessionManagerURL string
	AuditRetention    time.Duration
	AuditMaxBytes     int
	AWSRegion         string
	EventConsumer     bool
	EventQueueURL     string
}

func Load() Config {
	return Config{
		Port:              env("PORT", "8085"),
		StoreDriver:       env("STORE_DRIVER", "memory"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		SessionManagerURL: env("SESSION_MANAGER_URL", "http://localhost:8081"),
		AuditRetention:    secondsEnv("SESSION_AUDIT_RETENTION_SECONDS", 7*24*3600),
		AuditMaxBytes:     intEnv("SESSION_AUDIT_MAX_BYTES_PER_SESSION", 16*1024*1024),
		AWSRegion:         env("AWS_REGION", "ap-southeast-1"),
		EventConsumer:     boolEnv("AUDIT_EVENT_CONSUMER_ENABLED", false),
		EventQueueURL:     os.Getenv("AUDIT_EVENTS_QUEUE_URL"),
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func secondsEnv(key string, fallback int) time.Duration {
	v, err := strconv.Atoi(env(key, strconv.Itoa(fallback)))
	if err != nil {
		v = fallback
	}
	return time.Duration(v) * time.Second
}

func intEnv(key string, fallback int) int {
	v, err := strconv.Atoi(env(key, strconv.Itoa(fallback)))
	if err != nil {
		return fallback
	}
	return v
}

func boolEnv(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}
