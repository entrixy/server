package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"time"
)

// A webhook the server fires itself, on behalf of an owner or a guest.
type webhookJob struct {
	URL       string
	Secret    string
	NumberID  int64
	CallID    string
	HostID    int64
	Requester *Conn // whoever asked: the guest, or the owner for their own object
	UserKeyID int64
	// A guest's opening is also reported to the owner, silently, for the log.
	NotifyHost bool
	// "open" or "close". Bistable: the object is open/close, so the position
	// follows the command even when the receiver does not report one.
	Action   string
	Bistable bool
}

// The address a webhook may not be sent to. The check happens at the moment of
// connecting, on the address actually resolved: a name that looked public when
// the object was saved can start pointing inside the network later.
func privateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// Carrier-grade NAT and the "this network" range, which neither IsPrivate
	// nor IsLoopback covers.
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 100 && v4[1]&0xc0 == 64 {
			return true
		}
		if v4[0] == 0 || v4[0] == 169 && v4[1] == 254 {
			return true
		}
	}
	return false
}

var webhookClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 8 * time.Second,
			Control: func(network, address string, _ syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				if privateIP(net.ParseIP(host)) {
					return fmt.Errorf("webhook target not allowed")
				}
				return nil
			},
		}).DialContext,
		DisableKeepAlives:   true,
		MaxIdleConns:        4,
		TLSHandshakeTimeout: 8 * time.Second,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		// A redirect is the classic way around the address check: the first hop
		// looks public, the second points at the machine itself.
		return http.ErrUseLastResponse
	},
}

func whlog(format string, args ...any) {
	if cfg.WebhookLog == "" {
		return
	}
	f, err := os.OpenFile(cfg.WebhookLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

func fireWebhook(j webhookJob) {
	u, err := url.Parse(j.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		j.finish("danger", "webhook target not allowed", false)
		return
	}

	if j.Action != "close" {
		j.Action = "open"
	}
	payload := map[string]any{"action": j.Action, "object_id": j.NumberID}
	if j.Secret != "" {
		nonce := make([]byte, 8)
		rand.Read(nonce)
		ts := time.Now().Unix()
		payload["timestamp"] = ts
		payload["nonce"] = hex.EncodeToString(nonce)
		// The signature covers a canonical string rather than the JSON, so the
		// receiver need not reproduce the serialisation byte for byte.
		base := fmt.Sprintf("%d.%s.%s.%d", ts, payload["nonce"], j.Action, j.NumberID)
		mac := hmac.New(sha256.New, []byte(j.Secret))
		mac.Write([]byte(base))
		payload["signature"] = hex.EncodeToString(mac.Sum(nil))
	}
	body, _ := json.Marshal(payload)

	go func() {
		req, err := http.NewRequest("POST", j.URL, bytes.NewReader(body))
		if err != nil {
			j.finish("danger", "connect error: "+err.Error(), false)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := webhookClient.Do(req)
		if err != nil {
			whlog("call=%s error %v", j.CallID, err)
			j.finish("danger", "connect error: "+err.Error(), false)
			return
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

		var result map[string]any
		json.Unmarshal(raw, &result)
		level, _ := result["level"].(string)
		switch level {
		case "success", "warning", "danger", "info":
		default:
			if s, _ := result["status"].(string); s == "ok" {
				level = "success"
			} else {
				level = "danger"
			}
		}
		message, _ := result["message"].(string)
		if message == "" {
			message = string(raw)
			if message == "" {
				message = "no response"
			}
		}
		whlog("call=%s result level=%s msg=%.120s", j.CallID, level, message)

		// The position: from the answer, or — for an open/close object whose
		// receiver keeps silent — from the command that went through.
		pos, _ := result["position"].(string)
		if !validPosition(pos) && j.Bistable && level != "danger" {
			pos = "open"
			if j.Action == "close" {
				pos = "closed"
			}
		}
		if validPosition(pos) {
			applyCommandState(j.HostID, j.NumberID, pos)
			ci, _ := result["close_in"].(float64)
			scheduleWebhookForget(j.HostID, j.NumberID, pos, int(ci))
		}
		j.finish(level, message, true)
	}()
}

// The answer goes to whoever asked, and — for a guest's opening — to the owner
// as well, silently: it belongs in their log but must not sound an alert.
func (j webhookJob) finish(level, message string, logIt bool) {
	if j.Requester != nil {
		j.Requester.send(map[string]any{
			"type": "device_status", "call_id": j.CallID, "number_id": j.NumberID,
			"level": level, "message": message, "final": true,
		})
	}
	if j.NotifyHost {
		if h := hub.host(j.HostID); h != nil {
			h.send(map[string]any{
				"type": "device_status", "call_id": j.CallID, "number_id": j.NumberID,
				"user_key_id": j.UserKeyID, "level": level, "message": message,
				"final": true, "silent": true,
			})
		}
	}
	if logIt {
		exec(`INSERT INTO call_log (user_key_id, number_id, ts, status) VALUES (?, ?, NOW(), ?)`,
			j.UserKeyID, j.NumberID, "webhook_"+level)
	}
	hub.dropCall(j.CallID)
}
