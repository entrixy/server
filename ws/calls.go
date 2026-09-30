package main

import (
	"database/sql"
	"log"
	"time"
)

func validPosition(p string) bool {
	return p == "open" || p == "closed" || p == "unknown"
}

// ── A guest opens something ─────────────────────────────────────────────────

func guestCall(c *Conn, msg map[string]any) {
	if c.snapRole() != "guest" {
		return
	}
	numberID := num(msg, "number_id")
	userKeyID := c.snapUserKeyID()
	hostID := c.snapHostID()

	var mode sql.NullString
	var forceBusy sql.NullInt64
	queryRow(`SELECT mode, force_when_busy FROM user_keys WHERE id = ?`, userKeyID).
		Scan(&mode, &forceBusy)
	currentMode := mode.String
	if currentMode == "" {
		currentMode = "auto"
	}
	c.mu.Lock()
	c.keyMode = currentMode
	c.mu.Unlock()
	if currentMode == "off" {
		c.send(map[string]any{"type": "error", "reason": "disabled"})
		return
	}

	var (
		objType  sql.NullString
		whURL    sql.NullString
		whSecret sql.NullString
		whMode   sql.NullString
		devIDCol sql.NullInt64
		appOnly  sql.NullInt64
	)
	err := queryRow(`SELECT n.type, n.webhook_url, n.webhook_secret, n.webhook_mode, n.device_id, kn.native_only
	                 FROM key_numbers kn JOIN numbers n ON n.id = kn.number_id
	                 WHERE kn.user_key_id = ? AND kn.number_id = ?`, userKeyID, numberID).
		Scan(&objType, &whURL, &whSecret, &whMode, &devIDCol, &appOnly)
	if err != nil {
		c.send(map[string]any{"type": "error", "reason": "forbidden"})
		return
	}
	// "App only" object: a browser client does not open it.
	if appOnly.Int64 == 1 && !c.snapApp() {
		c.send(map[string]any{"type": "error", "reason": "native_only"})
		return
	}
	kind := objType.String
	if kind == "" {
		kind = "call"
	}

	var recent int
	queryRow(`SELECT COUNT(*) FROM call_log
	          WHERE user_key_id = ? AND ts > DATE_SUB(NOW(), INTERVAL 1 MINUTE)`, userKeyID).
		Scan(&recent)
	if recent >= cfg.RateLimitPerMin {
		c.send(map[string]any{"type": "error", "reason": "rate_limit"})
		return
	}

	callID := newCallID()
	hub.putCall(callID, &Call{
		GuestOID:  c.id,
		UserKeyID: userKeyID,
		NumberID:  numberID,
		// Whose call this is: only the owner of this object may confirm it, not
		// anyone who happens to hold an owner connection.
		HostID: hostID,
	})
	exec(`INSERT INTO call_log (user_key_id, number_id, ts, status) VALUES (?, ?, NOW(), ?)`,
		userKeyID, numberID, "requested")

	switch {
	// ── A webhook fired by the server ──
	case kind == "webhook" && whMode.String == "server" && whURL.String != "":
		fireWebhook(webhookJob{
			URL: whURL.String, Secret: whSecret.String,
			NumberID: numberID, CallID: callID, HostID: hostID,
			Requester: c, UserKeyID: userKeyID, NotifyHost: true,
		})
		c.send(map[string]any{"type": "call_status", "call_id": callID, "status": "sending"})

	// ── A controller ──
	case kind == "device" && devIDCol.Valid && devIDCol.Int64 > 0:
		dev := hub.device(devIDCol.Int64)
		if dev == nil {
			c.send(map[string]any{"type": "error", "reason": "device_offline"})
			hub.dropCall(callID)
			return
		}
		if call := hub.call(callID); call != nil {
			hub.mu.Lock()
			call.DeviceID = devIDCol.Int64
			hub.mu.Unlock()
		}
		if dev.sockE2EE {
			// The controller is asked for a nonce. The guest signs it with their own
			// key and sends sock_fire; the server relays a signature it cannot
			// produce itself.
			dev.send(map[string]any{"type": "sock_challenge_req",
				"command_id": callID, "number_id": numberID})
			c.send(map[string]any{"type": "call_status", "call_id": callID, "status": "challenge_pending"})
		} else {
			dev.send(map[string]any{"type": "device_command", "action": "open",
				"command_id": callID, "number_id": numberID})
			c.send(map[string]any{"type": "call_status", "call_id": callID, "status": "sent_to_device"})
		}
		if h := hub.host(hostID); h != nil {
			h.send(map[string]any{"type": "device_sent", "call_id": callID,
				"number_id": numberID, "user_key_id": userKeyID})
		}

	// ── A webhook fired by the owner's phone ──
	case kind == "webhook":
		h := hub.host(hostID)
		if h == nil {
			c.send(map[string]any{"type": "error", "reason": "host_offline"})
			hub.dropCall(callID)
			return
		}
		h.send(map[string]any{"type": "do_webhook", "call_id": callID,
			"number_id": numberID, "user_key_id": userKeyID})
		c.send(map[string]any{"type": "call_status", "call_id": callID, "status": "sent_to_host"})

	// ── A phone call ──
	default:
		h := hub.host(hostID)
		if h == nil {
			c.send(map[string]any{"type": "error", "reason": "host_offline"})
			hub.dropCall(callID)
			return
		}
		if currentMode == "confirm" {
			h.send(map[string]any{"type": "confirm_request", "call_id": callID,
				"number_id": numberID, "user_key_id": userKeyID})
			c.send(map[string]any{"type": "call_status", "call_id": callID, "status": "awaiting_confirm"})
		} else {
			h.send(map[string]any{"type": "do_call", "call_id": callID,
				"number_id": numberID, "user_key_id": userKeyID,
				"notify":          currentMode == "notify",
				"force_when_busy": forceBusy.Int64 == 1})
			c.send(map[string]any{"type": "call_status", "call_id": callID, "status": "requested"})
		}
	}
}

// ── The owner opens their own object ────────────────────────────────────────

func hostSelfWebhook(c *Conn, msg map[string]any) {
	if c.snapRole() != "host" {
		return
	}
	numberID := num(msg, "number_id")
	if numberID <= 0 {
		return
	}
	hostID := c.snapHostID()

	var (
		id       int64
		typ      sql.NullString
		whURL    sql.NullString
		whSecret sql.NullString
		whMode   sql.NullString
	)
	err := queryRow(`SELECT id, type, webhook_url, webhook_secret, webhook_mode
	                 FROM numbers WHERE id = ? AND host_id = ?`, numberID, hostID).
		Scan(&id, &typ, &whURL, &whSecret, &whMode)
	if err != nil || typ.String != "webhook" || whURL.String == "" {
		c.send(map[string]any{"type": "error", "reason": "not_webhook"})
		return
	}

	callID := newCallID()
	hub.putCall(callID, &Call{NumberID: numberID, HostID: hostID})
	fireWebhook(webhookJob{
		URL: whURL.String, Secret: whSecret.String,
		NumberID: numberID, CallID: callID, HostID: hostID,
		Requester: c, UserKeyID: 0, NotifyHost: false,
	})
	c.send(map[string]any{"type": "device_sent", "call_id": callID,
		"number_id": numberID,
		// The label is the owner's own and it is encrypted: the server has never
		// had it. Echo back whatever the sender gave, if any.
		"number_label": str(msg, "number_label"), "guest_label": ""})
}

func hostSelfCall(c *Conn, msg map[string]any) {
	if c.snapRole() != "host" {
		return
	}
	numberID := num(msg, "number_id")
	if numberID <= 0 {
		return
	}
	hostID := c.snapHostID()

	var (
		id  int64
		typ sql.NullString
		dev sql.NullInt64
	)
	err := queryRow(`SELECT id, type, device_id FROM numbers WHERE id = ? AND host_id = ?`,
		numberID, hostID).Scan(&id, &typ, &dev)
	if err != nil {
		c.send(map[string]any{"type": "error", "reason": "forbidden"})
		return
	}
	// Controllers only. The other kinds the owner handles locally: an ordinary
	// call through the dialer, a phone-mode webhook as a direct request.
	if typ.String != "device" || !dev.Valid || dev.Int64 == 0 {
		c.send(map[string]any{"type": "error", "reason": "not_device"})
		return
	}
	d := hub.device(dev.Int64)
	if d == nil {
		c.send(map[string]any{"type": "error", "reason": "device_offline"})
		return
	}

	callID := newCallID()
	hub.putCall(callID, &Call{
		HostOID: c.id, NumberID: numberID, HostID: hostID, DeviceID: dev.Int64,
	})
	if d.sockE2EE {
		d.send(map[string]any{"type": "sock_challenge_req",
			"command_id": callID, "number_id": numberID})
	} else {
		d.send(map[string]any{"type": "device_command", "action": "open",
			"command_id": callID, "number_id": numberID})
	}
	c.send(map[string]any{"type": "device_sent", "call_id": callID, "number_id": numberID})
}

func confirmResponse(c *Conn, msg map[string]any) {
	if c.snapRole() != "host" {
		return
	}
	callID := str(msg, "call_id")
	accept := boolOf(msg, "accept", false)
	info := hub.call(callID)
	if info == nil {
		return
	}
	// Only the owner of this object confirms. Checking the role alone would let
	// any owner who guessed a call number see someone else's request.
	if info.HostID != c.snapHostID() {
		return
	}
	guest := hub.guest(info.GuestOID)
	if accept {
		c.send(map[string]any{"type": "do_call", "call_id": callID,
			"number_id": info.NumberID, "user_key_id": info.UserKeyID, "notify": false})
		if guest != nil {
			guest.send(map[string]any{"type": "call_status", "call_id": callID, "status": "accepted"})
		}
	} else {
		if guest != nil {
			guest.send(map[string]any{"type": "call_status", "call_id": callID, "status": "declined"})
		}
		hub.dropCall(callID)
	}
}

func callStatus(c *Conn, msg map[string]any) {
	if c.snapRole() != "host" {
		return
	}
	callID := str(msg, "call_id")
	status := str(msg, "status")
	info := hub.call(callID)
	if info == nil {
		return
	}
	exec(`INSERT INTO call_log (user_key_id, number_id, ts, status) VALUES (?, ?, NOW(), ?)`,
		info.UserKeyID, info.NumberID, status)
	if g := hub.guest(info.GuestOID); g != nil {
		g.send(map[string]any{"type": "call_status", "call_id": callID, "status": status})
	}
	if status == "ended" || status == "error" {
		hub.dropCall(callID)
	}
}

// ── The state of a bistable object ──────────────────────────────────────────

// Applies a new position with a diff, a rate limit and a broadcast. Returns
// true when the state really changed and the broadcast went out.
func applyObjectState(hostID, numID int64, position string) bool {
	if !validPosition(position) {
		return false
	}
	var last sql.NullString
	var owner int64
	if err := queryRow(`SELECT last_state, host_id FROM numbers WHERE id = ?`, numID).
		Scan(&last, &owner); err != nil {
		return false
	}
	if owner != hostID || last.String == position {
		return false
	}

	// One broadcast per five seconds per object.
	hub.stateMu.Lock()
	if time.Since(hub.lastState[numID]) < 5*time.Second {
		hub.stateMu.Unlock()
		return false
	}
	hub.lastState[numID] = time.Now()
	hub.stateMu.Unlock()

	exec(`UPDATE numbers SET last_state = ?, last_state_at = NOW() WHERE id = ?`, position, numID)
	payload := map[string]any{
		"type": "obj_state_update", "num_id": numID,
		"position": position, "updated_at": time.Now().Unix(),
	}
	if h := hub.host(hostID); h != nil {
		h.send(payload)
	}
	rows, ok := query(`SELECT DISTINCT user_key_id FROM key_numbers WHERE number_id = ?`, numID)
	if !ok {
		return true
	}
	defer rows.Close()
	for rows.Next() {
		var keyID int64
		if rows.Scan(&keyID) != nil {
			continue
		}
		for _, g := range hub.guestsOfKey(keyID) {
			g.send(payload)
		}
	}
	return true
}

// ── The owner's queue ───────────────────────────────────────────────────────

// Something that must reach the owner while they are offline. It waits in the
// database rather than in memory, so a restart of the worker does not lose it.
func enqueueHostMsg(hostID int64, payload map[string]any) {
	if hostID <= 0 {
		return
	}
	var dedup any
	if payload["type"] == "ble_token_renew" {
		dedup = fmtDedup(payload)
	}
	b, err := jsonMarshal(payload)
	if err != nil {
		return
	}
	exec(`INSERT IGNORE INTO pending_host_msgs (host_id, payload, dedup_key, created_at)
	      VALUES (?, ?, ?, NOW())`, hostID, string(b), dedup)

	// A cap per owner keeps the queue from growing under abuse: renew is
	// deduplicated already, but fire_event with unique timestamps is not.
	const cap = 500
	var count int
	queryRow(`SELECT COUNT(*) FROM pending_host_msgs WHERE host_id = ?`, hostID).Scan(&count)
	if count > cap {
		exec(`DELETE FROM pending_host_msgs WHERE host_id = ? ORDER BY id ASC LIMIT ?`,
			hostID, count-cap)
	}
}

func flushHostQueue(host *Conn, hostID int64) {
	rows, ok := query(`SELECT id, payload FROM pending_host_msgs WHERE host_id = ? ORDER BY id ASC`,
		hostID)
	if !ok {
		return
	}
	type row struct {
		id      int64
		payload string
	}
	var list []row
	for rows.Next() {
		var r row
		if rows.Scan(&r.id, &r.payload) == nil {
			list = append(list, r)
		}
	}
	rows.Close()
	for _, r := range list {
		host.sendRaw([]byte(r.payload))
		exec(`DELETE FROM pending_host_msgs WHERE id = ?`, r.id)
	}
	if len(list) > 0 {
		log.Printf("queue: %d message(s) handed to host %d", len(list), hostID)
	}
}
