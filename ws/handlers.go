package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

// A greeting repeated oftener than this closes the connection without touching
// the database: while a websocket flaps a client could throw one at the server
// every second, and each costs a lookup.
const helloMinInterval = 5 * time.Second

var (
	reHex64  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	reNonce  = regexp.MustCompile(`^[a-f0-9]{16,64}$`)
	suiteSet = map[string]bool{"v1": true}
)

const suitePreferred = "v1"

func newCallID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func str(m map[string]any, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}

func num(m map[string]any, k string) int64 {
	switch v := m[k].(type) {
	case float64:
		return int64(v)
	case string:
		var n int64
		fmt.Sscan(v, &n)
		return n
	}
	return 0
}

func boolOf(m map[string]any, k string, def bool) bool {
	switch v := m[k].(type) {
	case bool:
		return v
	case float64:
		return v != 0
	}
	return def
}

func handleMessage(c *Conn, data []byte) {
	c.touch()

	var msg map[string]any
	if err := json.Unmarshal(data, &msg); err != nil || str(msg, "type") == "" {
		c.send(map[string]any{"type": "error", "reason": "bad_msg"})
		return
	}
	typ := str(msg, "type")

	if typ == "host_hello" || typ == "guest_hello" {
		key := "h:" + str(msg, "device_id")
		if typ == "guest_hello" {
			key = "g:" + str(msg, "key_id")
		}
		hub.helloMu.Lock()
		prev := hub.lastHello[key]
		now := time.Now()
		tooSoon := now.Sub(prev) < helloMinInterval
		if !tooSoon {
			hub.lastHello[key] = now
			if len(hub.lastHello) > 10000 {
				for k, t := range hub.lastHello {
					if now.Sub(t) > time.Minute {
						delete(hub.lastHello, k)
					}
				}
			}
		}
		hub.helloMu.Unlock()
		if tooSoon {
			// Closed quietly, with no answer: the client reconnects on its own
			// backoff, which grows with each attempt.
			c.close()
			return
		}
	}

	switch typ {
	case "host_hello":
		hostHello(c, msg)
	case "guest_hello":
		guestHello(c, msg)
	case "call":
		guestCall(c, msg)
	case "host_self_webhook":
		hostSelfWebhook(c, msg)
	case "host_self_call":
		hostSelfCall(c, msg)
	case "confirm_response":
		confirmResponse(c, msg)
	case "call_status":
		callStatus(c, msg)
	case "sock_challenge":
		sockChallenge(c, msg)
	case "sock_fire":
		sockFire(c, msg)
	case "sock_revoke":
		sockRevoke(c, msg)
	case "device_hello":
		deviceHello(c, msg)
	case "device_response", "device_status":
		deviceStatus(c, msg, typ)
	case "webhook_result":
		webhookResult(c, msg)
	case "obj_state_push":
		if c.snapRole() != "host" {
			return
		}
		numID := num(msg, "num_id")
		pos := str(msg, "position")
		if numID > 0 && validPosition(pos) {
			applyObjectState(c.snapHostID(), numID, pos)
		}
	case "avatar_request":
		avatarRequest(c, msg)
	case "avatar_data":
		avatarData(c, msg)
	case "ble_token_renew":
		bleTokenRenew(c, msg)
	case "ble_token_response":
		bleTokenResponse(c, msg)
	case "ble_fire_event":
		bleFireEvent(c, msg)
	case "ping":
		c.touch()
		c.send(map[string]any{"type": "pong"})
	}
}

// ── The owner's phone ────────────────────────────────────────────────────────

func hostHello(c *Conn, msg map[string]any) {
	deviceID := str(msg, "device_id")
	secret := str(msg, "device_secret")
	fcm := str(msg, "fcm_token")
	fp := str(msg, "device_fp")
	if deviceID == "" || secret == "" {
		c.close()
		return
	}

	var id int64
	var secretHash, boundFP sql.NullString
	err := queryRow(`SELECT id, secret_hash, bound_device_fp FROM hosts WHERE device_id = ?`,
		deviceID).Scan(&id, &secretHash, &boundFP)
	sum := sha256.Sum256([]byte(secret))
	if err != nil || !hmac.Equal([]byte(secretHash.String), []byte(hex.EncodeToString(sum[:]))) {
		c.sendThenClose(map[string]any{"type": "error", "reason": "auth"})
		return
	}

	c.mu.Lock()
	c.role = "host"
	c.hostID = id
	c.clientLang = str(msg, "lang")
	c.deviceFP = fp
	c.mu.Unlock()

	hub.mu.Lock()
	hub.hosts[id] = c
	hub.mu.Unlock()

	// Moving to another phone: the new handset took the access and this one is
	// the old one. We say so here rather than waiting to be asked. An empty
	// fingerprint belongs to an older client that knows nothing of this.
	if fp != "" && boundFP.String != "" && !hmac.Equal([]byte(boundFP.String), []byte(fp)) {
		log.Printf("evicted on connect: host %d, fingerprint %.10s", id, fp)
		c.sendThenClose(map[string]any{"type": "evicted"})
		return
	}

	exec(`UPDATE hosts SET last_seen = NOW(),
	      fcm_token = COALESCE(NULLIF(?, ''), fcm_token) WHERE id = ?`, fcm, id)

	c.send(map[string]any{"type": "host_ok"})

	online := []int64{}
	for _, d := range hub.allDevices() {
		if d.snapHostID() == id {
			online = append(online, d.snapDeviceID())
		}
	}
	c.send(map[string]any{"type": "devices_online", "device_ids": online})

	for _, g := range hub.guestsOfHost(id) {
		g.send(map[string]any{"type": "host_status", "online": true})
	}

	flushHostQueue(c, id)
}

// ── The guest's phone ────────────────────────────────────────────────────────

func guestHello(c *Conn, msg map[string]any) {
	deviceFP := str(msg, "device_fp")
	hash := strings.ToLower(str(msg, "key_id"))
	ts := str(msg, "ts")
	nonce := str(msg, "nonce")
	sig := str(msg, "sig")
	suite := str(msg, "suite")
	if suite == "" {
		suite = suitePreferred
	}
	if !reHex64.MatchString(hash) || sig == "" {
		c.close()
		return
	}
	if !suiteSet[suite] {
		c.close()
		return
	}
	var tsN int64
	fmt.Sscan(ts, &tsN)
	if tsN <= 0 || abs64(time.Now().Unix()-tsN) > 300 {
		c.close()
		return
	}
	if !reNonce.MatchString(nonce) {
		c.close()
		return
	}

	var (
		ukID, hostID  int64
		mode          sql.NullString
		boundFP       sql.NullString
		nativeOnly    sql.NullInt64
		orgID         sql.NullInt64
		expiresAt     sql.NullString
		signPub       []byte
		signSuite     sql.NullString
		signPubDevice []byte
	)
	err := queryRow(`SELECT uk.id, uk.host_id, uk.mode, uk.bound_device_fp, uk.native_only,
	                        uk.org_id, uk.expires_at, uk.sign_pub, uk.sign_suite, uk.sign_pub_device
	                 FROM user_keys uk WHERE uk.key_hash = ? AND uk.enabled = 1`, hash).
		Scan(&ukID, &hostID, &mode, &boundFP, &nativeOnly, &orgID, &expiresAt,
			&signPub, &signSuite, &signPubDevice)
	if err != nil || len(signPub) == 0 {
		c.sendThenClose(map[string]any{"type": "error", "reason": "bad_key"})
		return
	}
	keySuite := signSuite.String
	if keySuite == "" {
		keySuite = "v1"
	}
	if keySuite != suite {
		c.sendThenClose(map[string]any{"type": "error", "reason": "bad_key"})
		return
	}

	fpHash := sha256.Sum256([]byte(deviceFP))
	material := suite + "." + hash + "." + ts + "." + nonce + ".guest_hello." + hex.EncodeToString(fpHash[:])
	// A key that has settled on a handset is checked only against that handset's
	// own pair; the pair derived from the link is dead by then.
	pub := signPub
	if len(signPubDevice) == 32 {
		pub = signPubDevice
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(raw) != 64 || len(pub) != 32 ||
		!ed25519.Verify(ed25519.PublicKey(pub), []byte(material), raw) {
		c.sendThenClose(map[string]any{"type": "error", "reason": "bad_key"})
		return
	}

	// One-time number: an overheard greeting does not pass twice.
	if _, err := db.Exec(`INSERT INTO guest_nonces (key_hash, nonce, used_at) VALUES (?,?,NOW())`,
		hash, nonce); err != nil {
		c.sendThenClose(map[string]any{"type": "error", "reason": "bad_key"})
		return
	}

	// A company's key lives on the company's own server and works only through
	// api/company.php with its secret.
	if orgID.Valid && orgID.Int64 > 0 {
		c.sendThenClose(map[string]any{"type": "error", "reason": "org_key"})
		return
	}
	if expiresAt.Valid && expiresAt.String != "" {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", expiresAt.String, time.Local); err == nil &&
			t.Before(time.Now()) {
			c.sendThenClose(map[string]any{"type": "error", "reason": "expired"})
			return
		}
	}

	// A key for the app only. The app signs its greeting with an attestation the
	// browser client cannot produce.
	if nativeOnly.Int64 == 1 {
		attestTS := num(msg, "attest_ts")
		attest := str(msg, "attest")
		mac := hmac.New(sha256.New, []byte(cfg.AttestSecret))
		fmt.Fprintf(mac, "%s|%d", hash, attestTS)
		expect := hex.EncodeToString(mac.Sum(nil))
		if attestTS <= 0 || abs64(time.Now().Unix()-attestTS) > 120 || attest == "" ||
			!hmac.Equal([]byte(expect), []byte(attest)) {
			c.sendThenClose(map[string]any{"type": "error", "reason": "native_only"})
			return
		}
	}

	// The key belongs to one handset. Nothing bound yet means the first one to
	// connect is bound here; a different fingerprint afterwards is turned away.
	bound := boundFP.String
	if bound == "" && deviceFP != "" {
		exec(`UPDATE user_keys SET bound_device_fp = ?, bound_at = NOW() WHERE id = ?`, deviceFP, ukID)
		bound = deviceFP
	}
	if bound != "" && (deviceFP == "" || !hmac.Equal([]byte(bound), []byte(deviceFP))) {
		c.sendThenClose(map[string]any{"type": "error", "reason": "already_bound"})
		return
	}

	nums := keyNumbers(ukID)

	keyMode := mode.String
	if keyMode == "" {
		keyMode = "auto"
	}
	c.mu.Lock()
	c.role = "guest"
	c.userKeyID = ukID
	c.hostID = hostID
	c.keyMode = keyMode
	c.mu.Unlock()
	hub.mu.Lock()
	hub.guests[c.id] = c
	hub.mu.Unlock()

	c.send(map[string]any{"type": "guest_ok", "numbers": nums, "mode": keyMode})

	hostOnline := hub.host(hostID) != nil
	status := map[string]any{"type": "host_status", "online": hostOnline}
	if !hostOnline {
		var lastSeen sql.NullString
		if err := queryRow(`SELECT last_seen FROM hosts WHERE id = ?`, hostID).Scan(&lastSeen); err == nil &&
			lastSeen.Valid && lastSeen.String != "" {
			status["last_seen"] = lastSeen.String
		}
	}
	c.send(status)

	online := []int64{}
	for _, d := range hub.allDevices() {
		if d.snapHostID() == hostID {
			online = append(online, d.snapDeviceID())
		}
	}
	c.send(map[string]any{"type": "devices_online", "device_ids": online})
}

// The objects a key opens, as the client expects them: the sensitive part of
// every object travels inside data_cipher, which the server cannot read.
func keyNumbers(userKeyID int64) []map[string]any {
	rows, ok := query(`SELECT n.id, n.type, n.device_id, n.data_cipher
	                   FROM key_numbers kn JOIN numbers n ON n.id = kn.number_id
	                   WHERE kn.user_key_id = ?`, userKeyID)
	if !ok {
		return []map[string]any{}
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var (
			id       int64
			typ      sql.NullString
			deviceID sql.NullInt64
			cipher   sql.NullString
		)
		if err := rows.Scan(&id, &typ, &deviceID, &cipher); err != nil {
			continue
		}
		item := map[string]any{"id": id, "type": typ.String}
		if deviceID.Valid {
			item["device_id"] = deviceID.Int64
		} else {
			item["device_id"] = nil
		}
		if cipher.Valid {
			item["data_cipher"] = cipher.String
		} else {
			item["data_cipher"] = nil
		}
		out = append(out, item)
	}
	return out
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
