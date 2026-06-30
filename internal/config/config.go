// Package config carga la configuración del agente desde:
//  1. flags CLI
//  2. variables de entorno (HD360_SCANNER_*)
//  3. archivo /etc/hd360-scanner/agent.yaml (o ./agent.yaml en dev)
//
// Precedencia: flags > env > archivo > defaults.
package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Config — todo lo que necesita el agente para funcionar
type Config struct {
	// Identidad
	ScannerID    string `mapstructure:"scanner_id"`
	AgentSecret  string `mapstructure:"agent_secret"`

	// Endpoint del cloud (ej: https://kuanta.helpdesk360.cr/api/v1)
	CloudURL string `mapstructure:"cloud_url"`

	// Versión del agente (poblada al build con -ldflags)
	AgentVersion string `mapstructure:"agent_version"`

	// Intervalos en segundos
	HeartbeatIntervalSec int `mapstructure:"heartbeat_interval_sec"`
	HTTPTimeoutSec       int `mapstructure:"http_timeout_sec"`

	// Logging
	LogLevel  string `mapstructure:"log_level"`  // debug | info | warn | error
	LogFormat string `mapstructure:"log_format"` // text | json

	// Dev-only: skip TLS verify del cloud (NO usar en prod)
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify"`
}

// Defaults aplicados cuando ni env ni archivo definen el campo
func setDefaults(v *viper.Viper) {
	v.SetDefault("heartbeat_interval_sec", 60)
	v.SetDefault("http_timeout_sec", 30)
	v.SetDefault("log_level", "info")
	v.SetDefault("log_format", "text")
	v.SetDefault("agent_version", "dev")
	v.SetDefault("insecure_skip_verify", false)
}

// Load lee config desde archivo + env. Archivo es opcional si todas las
// claves obligatorias están en env.
func Load(configPath string) (*Config, error) {
	v := viper.New()
	setDefaults(v)

	// Env: HD360_SCANNER_SCANNER_ID, HD360_SCANNER_AGENT_SECRET, etc.
	// IMPORTANTE: viper.Unmarshal NO lee env vars vía AutomaticEnv() sin
	// un BindEnv explícito por cada key. Por eso bindeamos manual cada una.
	v.SetEnvPrefix("HD360_SCANNER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	for _, k := range []string{
		"scanner_id", "agent_secret", "cloud_url", "agent_version",
		"heartbeat_interval_sec", "http_timeout_sec",
		"log_level", "log_format", "insecure_skip_verify",
	} {
		_ = v.BindEnv(k)
	}

	// Archivo opcional
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("agent")
		v.SetConfigType("yaml")
		v.AddConfigPath("/etc/hd360-scanner/")
		v.AddConfigPath(".")
	}
	if err := v.ReadInConfig(); err != nil {
		// Falta archivo solo es error si las claves obligatorias no están en env.
		if _, isNotFound := err.(viper.ConfigFileNotFoundError); !isNotFound {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate verifica que los campos obligatorios estén presentes
func (c *Config) Validate() error {
	if c.ScannerID == "" {
		return fmt.Errorf("scanner_id is required (env HD360_SCANNER_SCANNER_ID or config file)")
	}
	if c.AgentSecret == "" {
		return fmt.Errorf("agent_secret is required (env HD360_SCANNER_AGENT_SECRET or config file)")
	}
	if c.CloudURL == "" {
		return fmt.Errorf("cloud_url is required (e.g. https://kuanta.helpdesk360.cr/api/v1)")
	}
	if !strings.HasPrefix(c.CloudURL, "http://") && !strings.HasPrefix(c.CloudURL, "https://") {
		return fmt.Errorf("cloud_url must start with http:// or https://")
	}
	c.CloudURL = strings.TrimRight(c.CloudURL, "/")
	return nil
}

// Hostname devuelve el hostname del OS donde corre el agente (best-effort)
func Hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
