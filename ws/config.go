package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
)

// Settings the worker needs. Everything comes from the environment, so the same
// binary serves a container and a systemd unit; -config points at a JSON file
// with the same names for an installation that would rather keep them in one
// place. That file is produced from the server's own configuration, so the
// two halves never disagree about the database.
type Config struct {
	Addr            string `json:"ws_addr"`
	DBHost          string `json:"db_host"`
	DBName          string `json:"db_name"`
	DBUser          string `json:"db_user"`
	DBPass          string `json:"db_pass"`
	AttestSecret    string `json:"app_attest_secret"`
	RateLimitPerMin int    `json:"rate_limit_per_min"`
	PromoBase       string `json:"promo_base_url"`
	WebhookLog      string `json:"webhook_log"`
	AccessCode      string `json:"access_code"`
}

func loadConfig() Config {
	path := flag.String("config", "", "JSON file with the settings")
	flag.Parse()

	// WS_HOST and WS_PORT are what the compose file sets for the web half as
	// well; WS_ADDR wins when it is given.
	addr := env("WS_ADDR", "")
	if addr == "" {
		addr = env("WS_HOST", "127.0.0.1") + ":" + env("WS_PORT", "8095")
	}
	c := Config{
		Addr:            addr,
		DBHost:          env("DB_HOST", "127.0.0.1"),
		DBName:          env("DB_NAME", ""),
		DBUser:          env("DB_USER", ""),
		DBPass:          env("DB_PASS", ""),
		AttestSecret:    env("APP_ATTEST_SECRET", ""),
		RateLimitPerMin: envInt("RATE_LIMIT_PER_MIN", 60),
		PromoBase:       env("PROMO_BASE_URL", ""),
		WebhookLog:      env("WEBHOOK_LOG", ""),
		AccessCode:      env("ACCESS_CODE", ""),
	}
	if *path != "" {
		b, err := os.ReadFile(*path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(2)
		}
		if err := json.Unmarshal(b, &c); err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			os.Exit(2)
		}
	}
	if c.DBName == "" || c.DBUser == "" {
		fmt.Fprintln(os.Stderr, "config: the database is not configured (DB_NAME, DB_USER)")
		os.Exit(2)
	}
	if c.RateLimitPerMin <= 0 {
		c.RateLimitPerMin = 60
	}
	return c
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
