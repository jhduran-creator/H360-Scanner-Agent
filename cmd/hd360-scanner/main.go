// Package main — entry point del agente hd360-scanner.
//
// Subcomandos:
//   hd360-scanner setup        — wizard interactivo para crear /etc/hd360-scanner/agent.yaml
//   hd360-scanner run          — corre el daemon (heartbeat loop + discovery según schedule)
//   hd360-scanner discover     — one-shot: pide config + ejecuta UN scan + report + exit
//   hd360-scanner version      — print build version
//
// Build con: go build -ldflags="-X main.version=1.0.0" -o hd360-scanner ./cmd/hd360-scanner
package main

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/kuanta-bridge/hd360-scanner/internal/config"
	"github.com/kuanta-bridge/hd360-scanner/internal/discovery"
	"github.com/kuanta-bridge/hd360-scanner/internal/transport"
	"github.com/kuanta-bridge/hd360-scanner/internal/types"
)

// Inyectado vía -ldflags en build
var version = "dev"

var (
	flagConfigPath string
	flagLogLevel   string
)

func main() {
	root := &cobra.Command{
		Use:   "hd360-scanner",
		Short: "HelpDesk 360 LAN discovery agent",
		Long: `Agente que descubre activos en la LAN del cliente y los reporta al
cloud HD360 vía HTTPS+HMAC.`,
		Version: version,
	}
	root.PersistentFlags().StringVar(&flagConfigPath, "config", "", "path a agent.yaml (default: /etc/hd360-scanner/agent.yaml o ./agent.yaml)")
	root.PersistentFlags().StringVar(&flagLogLevel, "log-level", "", "override log level (debug|info|warn|error)")

	root.AddCommand(setupCmd(), runCmd(), discoverCmd(), versionCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// ─── Subcomandos ─────────────────────────────────────────────────────────

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("hd360-scanner %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		},
	}
}

func setupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Wizard interactivo para crear el archivo de config",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Configuración del agente HD360 Scanner")
			fmt.Println("=======================================")
			reader := bufio.NewReader(os.Stdin)

			scannerID := prompt(reader, "Scanner ID (UUID del cloud)")
			agentSecret := prompt(reader, "Agent Secret (recibido al crear scanner en cloud)")
			cloudURL := promptDefault(reader, "Cloud URL", "https://kuanta.helpdesk360.cr/api/v1")

			path := flagConfigPath
			if path == "" {
				path = "./agent.yaml"
			}

			content := fmt.Sprintf(`# HelpDesk 360 Scanner Agent — config
# Generado por 'hd360-scanner setup' el %s

scanner_id: %s
agent_secret: %s
cloud_url: %s

heartbeat_interval_sec: 60
http_timeout_sec: 30
log_level: info
log_format: text
`, time.Now().Format(time.RFC3339), scannerID, agentSecret, cloudURL)

			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				return fmt.Errorf("write config: %w", err)
			}
			fmt.Printf("\nOK — config escrito a %s (chmod 600)\n", path)
			fmt.Println("Probá: hd360-scanner discover")
			return nil
		},
	}
}

func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Corre el agente como daemon (heartbeat + discovery loop)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(flagConfigPath)
			if err != nil {
				return err
			}
			if flagLogLevel != "" {
				cfg.LogLevel = flagLogLevel
			}
			cfg.AgentVersion = version
			log := newLogger(cfg)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Graceful shutdown en SIGINT/SIGTERM
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				sig := <-sigs
				log.Info("recibido signal, cerrando...", "sig", sig)
				cancel()
			}()

			client := transport.New(cfg)
			runner := discovery.NewRunner(log)

			log.Info("agente iniciado",
				"scanner_id", cfg.ScannerID,
				"cloud_url", cfg.CloudURL,
				"version", version,
			)

			heartbeatTicker := time.NewTicker(time.Duration(cfg.HeartbeatIntervalSec) * time.Second)
			defer heartbeatTicker.Stop()

			// Estado: última config conocida y schedule timer
			var lastConfig types.ScannerConfig
			var lastCreds []types.Credential
			var discoveryTicker *time.Ticker
			defer func() {
				if discoveryTicker != nil {
					discoveryTicker.Stop()
				}
			}()

			// Hacer un heartbeat + fetch creds + (si schedule lo permite) un primer scan inmediato
			doHeartbeat := func() {
				ctxHb, cancelHb := context.WithTimeout(ctx, 30*time.Second)
				defer cancelHb()
				resp, err := client.Heartbeat(ctxHb, types.HeartbeatReq{
					AgentVersion: version,
					AgentOS:      runtime.GOOS,
					Status:       "active",
				})
				if err != nil {
					log.Warn("heartbeat falló", "err", err)
					return
				}
				lastConfig = resp.Config
				log.Debug("heartbeat OK", "ranges", len(resp.Config.Ranges), "protocols", resp.Config.EnabledProtocols)
				// Refresh creds (silent ok si no hay credentials configuradas aún)
				if credResp, err := client.Credentials(ctxHb); err == nil {
					lastCreds = credResp.Credentials
				}
				// Ajustar el ticker de discovery según schedule
				newInterval := scheduleToInterval(resp.Config.Schedule)
				if newInterval > 0 {
					if discoveryTicker != nil {
						discoveryTicker.Reset(newInterval)
					} else {
						discoveryTicker = time.NewTicker(newInterval)
					}
				}
			}

			doDiscovery := func() {
				if len(lastConfig.Ranges) == 0 {
					log.Debug("discovery skip: no hay rangos configurados todavía")
					return
				}
				report := runner.Run(ctx, lastConfig, lastCreds)
				if len(report.Hosts) == 0 && len(report.Errors) == 0 {
					log.Info("discovery sin resultados, no se manda al cloud")
					return
				}
				ctxRep, cancelRep := context.WithTimeout(ctx, 60*time.Second)
				defer cancelRep()
				resp, err := client.DiscoveryReport(ctxRep, report)
				if err != nil {
					log.Error("discovery-report falló", "err", err)
					return
				}
				log.Info("discovery-report enviado", "accepted", resp.Accepted, "errors", len(resp.Errors))
			}

			doHeartbeat()  // primer heartbeat al arrancar

			for {
				select {
				case <-ctx.Done():
					return nil
				case <-heartbeatTicker.C:
					doHeartbeat()
				case <-tickerChan(discoveryTicker):
					doDiscovery()
				}
			}
		},
	}
}

func discoverCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "discover",
		Short: "One-shot: heartbeat + discovery + report + exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(flagConfigPath)
			if err != nil {
				return err
			}
			if flagLogLevel != "" {
				cfg.LogLevel = flagLogLevel
			}
			cfg.AgentVersion = version
			log := newLogger(cfg)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			client := transport.New(cfg)

			hbResp, err := client.Heartbeat(ctx, types.HeartbeatReq{
				AgentVersion: version,
				AgentOS:      runtime.GOOS,
				Status:       "active",
			})
			if err != nil {
				return fmt.Errorf("heartbeat: %w", err)
			}
			log.Info("heartbeat OK", "ranges", len(hbResp.Config.Ranges))

			if len(hbResp.Config.Ranges) == 0 {
				return fmt.Errorf("scanner sin rangos configurados — configurar desde la UI cloud")
			}

			credResp, _ := client.Credentials(ctx)
			var creds []types.Credential
			if credResp != nil {
				creds = credResp.Credentials
			}

			runner := discovery.NewRunner(log)
			report := runner.Run(ctx, hbResp.Config, creds)
			resp, err := client.DiscoveryReport(ctx, report)
			if err != nil {
				return fmt.Errorf("discovery-report: %w", err)
			}
			fmt.Printf("OK — %d hosts reportados, %d errors\n", resp.Accepted, len(resp.Errors))
			return nil
		},
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────

func prompt(r *bufio.Reader, label string) string {
	fmt.Printf("%s: ", label)
	line, _ := r.ReadString('\n')
	return strings.TrimSpace(line)
}

func promptDefault(r *bufio.Reader, label, defaultVal string) string {
	fmt.Printf("%s [%s]: ", label, defaultVal)
	line, _ := r.ReadString('\n')
	s := strings.TrimSpace(line)
	if s == "" {
		return defaultVal
	}
	return s
}

func newLogger(cfg *config.Config) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if cfg.LogFormat == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

func scheduleToInterval(s string) time.Duration {
	switch s {
	case "every_5_min":
		return 5 * time.Minute
	case "hourly":
		return time.Hour
	case "daily":
		return 24 * time.Hour
	}
	return 0  // 'manual' o vacío
}

// tickerChan retorna un channel nil-safe (un ticker nil produce un chan
// que nunca dispara, sin panic).
func tickerChan(t *time.Ticker) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}
