// Package transport implementa el HTTP client autenticado por HMAC que
// se comunica con el cloud HD360. Firma cada request idénticamente a
// como el backend lo valida en ScannerSignatureGuard:
//
//   payload := METHOD + "\n" + PATH + "\n" + TIMESTAMP + "\n" + RAW_BODY
//   signature := hex(HMAC-SHA256(payload, agent_secret))
//
// Headers obligatorios:
//   X-HD360-Scanner-Id: <uuid>
//   X-HD360-Timestamp: <unix epoch seconds>
//   X-HD360-Signature: <hex>
package transport

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/kuanta-bridge/hd360-scanner/internal/config"
	"github.com/kuanta-bridge/hd360-scanner/internal/types"
)

// Client — wrapper del http.Client con HMAC sign automático
type Client struct {
	cfg  *config.Config
	http *http.Client
}

// New construye Client a partir de la config validada
func New(cfg *config.Config) *Client {
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout: time.Duration(cfg.HTTPTimeoutSec) * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: cfg.InsecureSkipVerify,
				},
				MaxIdleConns:        4,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// Heartbeat envía POST /scanner-inbound/heartbeat
func (c *Client) Heartbeat(ctx context.Context, req types.HeartbeatReq) (*types.HeartbeatResp, error) {
	var resp types.HeartbeatResp
	if err := c.do(ctx, "POST", "/scanner-inbound/heartbeat", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Credentials envía GET /scanner-inbound/credentials
func (c *Client) Credentials(ctx context.Context) (*types.CredentialsResp, error) {
	var resp types.CredentialsResp
	if err := c.do(ctx, "GET", "/scanner-inbound/credentials", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DiscoveryReport envía POST /scanner-inbound/discovery-report
func (c *Client) DiscoveryReport(ctx context.Context, req types.DiscoveryReportReq) (*types.DiscoveryReportResp, error) {
	var resp types.DiscoveryReportResp
	if err := c.do(ctx, "POST", "/scanner-inbound/discovery-report", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// do hace la request HTTP con HMAC sign + parseo de respuesta
func (c *Client) do(ctx context.Context, method, path string, body, out interface{}) error {
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		bodyBytes = b
	}

	fullURL := c.cfg.CloudURL + path
	// Extraer solo el path para el HMAC (sin host)
	u, err := url.Parse(fullURL)
	if err != nil {
		return fmt.Errorf("parse url: %w", err)
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := sign(method, u.RequestURI(), timestamp, bodyBytes, c.cfg.AgentSecret)

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("X-HD360-Scanner-Id", c.cfg.ScannerID)
	req.Header.Set("X-HD360-Timestamp", timestamp)
	req.Header.Set("X-HD360-Signature", signature)
	if bodyBytes != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "hd360-scanner/"+c.cfg.AgentVersion)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, string(respBody))
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("unmarshal response: %w (body=%s)", err, string(respBody))
		}
	}
	return nil
}

// sign computa HMAC-SHA256 hex del payload canónico.
// El path debe ser request URI (path + query si existe) sin el host.
// EXACTAMENTE el mismo algoritmo que ScannerSignatureGuard del backend.
func sign(method, requestURI, timestamp string, body []byte, secret string) string {
	payload := method + "\n" + requestURI + "\n" + timestamp + "\n" + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
