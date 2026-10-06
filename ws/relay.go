package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// One renewal request per object and key in the queue at a time: a guest whose
// websocket flaps could otherwise leave a thousand identical rows behind.
func fmtDedup(payload map[string]any) string {
	return fmt.Sprintf("renew:%d:%d", num(payload, "ble_id"), num(payload, "user_key_id"))
}

// ── The encrypted socket ────────────────────────────────────────────────────
//
// The server relays the challenge and the signature between the controller and
// whoever is opening, blindly. It holds neither the guest key nor the owner's
// secret, so it cannot produce an opening of its own.

func sockChallenge(c *Conn, msg map[string]any) {
	if c.snapRole() != "device" {
		return
	}
	cid := str(msg, "command_id")
	info := hub.call(cid)
	if info == nil || info.DeviceID != c.snapDeviceID() {
		return
	}
	var target *Conn
	if info.GuestOID != 0 {
		target = hub.guest(info.GuestOID)
	} else if info.HostOID != 0 {
		if h := hub.host(info.HostID); h != nil && h.id == info.HostOID {
			target = h
		}
	}
	if target != nil {
		target.send(map[string]any{
			"type": "sock_challenge", "command_id": cid,
			"number_id": info.NumberID, "nonce": str(msg, "nonce"),
		})
	}
}

func sockFire(c *Conn, msg map[string]any) {
	role := c.snapRole()
	if role != "guest" && role != "host" {
		return
	}
	cid := str(msg, "command_id")
	info := hub.call(cid)
	// Only the author of the call, and only to the controller it was aimed at.
	if info == nil || (info.GuestOID != c.id && info.HostOID != c.id) {
		return
	}
	dev := hub.device(info.DeviceID)
	if dev == nil {
		c.send(map[string]any{"type": "error", "reason": "device_offline"})
		return
	}
	fire := map[string]any{
		"type": "sock_fire", "command_id": cid, "number_id": info.NumberID,
		"token": str(msg, "token"), "owner_sig": str(msg, "owner_sig"),
		"guest_id": num(msg, "guest_id"), "nonce": str(msg, "nonce"),
		"proof": str(msg, "proof"),
	}
	// The action travels as the signer sent it: a close is signed over
	// nonce||"close", so changing it here only makes the controller refuse.
	if str(msg, "action") == "close" {
		fire["action"] = "close"
	}
	dev.send(fire)
}

// The owner blocks or unblocks a guest on one controller, signed with their own
// secret and versioned. The server keeps the latest state to hand to a board
// that was offline, and relays it: it can neither forge such a decision nor
// revive one that was revoked.
func sockRevoke(c *Conn, msg map[string]any) {
	if c.snapRole() != "host" {
		return
	}
	numberID := num(msg, "number_id")
	guestID := num(msg, "guest_id")
	version := num(msg, "version")
	revoked := int64(1)
	if !boolOf(msg, "revoked", true) {
		revoked = 0
	}
	sig := str(msg, "sig")
	if numberID <= 0 || guestID <= 0 || version <= 0 || sig == "" {
		return
	}
	var devID sql.NullInt64
	if err := queryRow(`SELECT device_id FROM numbers
	                    WHERE id = ? AND host_id = ? AND type = 'device'`,
		numberID, c.snapHostID()).Scan(&devID); err != nil || !devID.Valid || devID.Int64 == 0 {
		return
	}
	exec(`INSERT INTO device_revokes (device_id, guest_id, version, revoked, sig)
	      VALUES (?, ?, ?, ?, ?)
	      ON DUPLICATE KEY UPDATE
	        revoked = IF(VALUES(version) > version, VALUES(revoked), revoked),
	        sig     = IF(VALUES(version) > version, VALUES(sig), sig),
	        version = GREATEST(version, VALUES(version))`,
		devID.Int64, guestID, version, revoked, sig)
	if dev := hub.device(devID.Int64); dev != nil {
		dev.send(map[string]any{"type": "sock_revoke", "guest_id": guestID,
			"version": version, "revoked": revoked, "sig": sig})
	}
}

// ── Controllers ─────────────────────────────────────────────────────────────

func deviceHello(c *Conn, msg map[string]any) {
	key := str(msg, "device_key")
	secret := str(msg, "device_secret")
	if key == "" || secret == "" {
		c.close()
		return
	}
	var id, hostID int64
	var secretHash sql.NullString
	err := queryRow(`SELECT id, host_id, secret_hash FROM devices WHERE device_key = ?`, key).
		Scan(&id, &hostID, &secretHash)
	if err != nil || !sameHash(secretHash.String, secret) {
		c.sendThenClose(map[string]any{"type": "error", "reason": "auth"})
		return
	}
	c.mu.Lock()
	c.role = "device"
	c.deviceID = id
	c.hostID = hostID
	// Whether the firmware speaks the encrypted protocol. Older boards do not
	// send the field and go on taking a plain command.
	c.sockE2EE = boolOf(msg, "e2ee", false)
	// Firmware that takes its keepalive period from the server says so; older
	// boards ping every 30 s whatever we tell them, and are judged by that.
	c.pingS = 30
	if boolOf(msg, "ping_ctl", false) {
		c.pingS = cfg.DevicePingS
	}
	c.mu.Unlock()
	hub.mu.Lock()
	hub.devices[id] = c
	hub.mu.Unlock()

	exec(`UPDATE devices SET last_seen = NOW() WHERE id = ?`, id)
	// hb_interval — how often the board should report in. Fixed for now; with
	// many boards it becomes a function of their number.
	c.send(map[string]any{"type": "device_ok", "hb_interval": 300, "ping_s": cfg.DevicePingS})

	// Catch up on revocations accumulated while the board was offline. It
	// applies them by version and ignores the stale ones.
	if rows, ok := query(`SELECT guest_id, version, revoked, sig FROM device_revokes
	                      WHERE device_id = ?`, id); ok {
		for rows.Next() {
			var gid, ver, rev int64
			var sig sql.NullString
			if rows.Scan(&gid, &ver, &rev, &sig) != nil {
				continue
			}
			c.send(map[string]any{"type": "sock_revoke", "guest_id": gid,
				"version": ver, "revoked": rev, "sig": sig.String})
		}
		rows.Close()
	}

	online, _ := json.Marshal(map[string]any{
		"type": "device_online", "device_id": id, "online": true,
	})
	if h := hub.host(hostID); h != nil {
		h.sendRaw(online)
	}
	for _, g := range hub.guestsOfHost(hostID) {
		g.sendRaw(online)
	}
}

func deviceStatus(c *Conn, msg map[string]any, typ string) {
	if c.snapRole() != "device" {
		return
	}
	commandID := str(msg, "command_id")
	message := str(msg, "message")

	var level string
	var final bool
	if typ == "device_status" {
		level = str(msg, "level")
		switch level {
		case "success", "warning", "danger", "info":
		default:
			level = "info"
		}
		final = boolOf(msg, "final", true)
	} else {
		if str(msg, "status") == "ok" || msg["status"] == nil {
			level = "success"
		} else {
			level = "danger"
		}
		final = true
	}

	// A reply counts only for the command it belongs to. Without this a board
	// naming someone else's command would send an unrelated guest an "opened"
	// and litter a log that is not theirs.
	info := hub.call(commandID)
	if info != nil && info.DeviceID != c.snapDeviceID() {
		info = nil
	}

	var numberID any
	if info != nil {
		numberID = info.NumberID
	}
	// The board's own event — the exit button, the limit switch, auto-close.
	// No command stands behind it, so the object is found by the controller.
	event := str(msg, "event")
	switch event {
	case "button", "limit", "auto":
	default:
		event = ""
	}
	if info == nil {
		var nid int64
		if queryRow(`SELECT id FROM numbers WHERE device_id = ? AND type = 'device'`,
			c.snapDeviceID()).Scan(&nid) == nil {
			numberID = nid
		}
	}
	if info != nil {
		if g := hub.guest(info.GuestOID); g != nil {
			g.send(map[string]any{"type": "device_status", "call_id": commandID,
				"number_id": numberID, "level": level, "message": message, "final": final})
		}
	}
	// The owner hears about everything, bound commands and spontaneous events
	// alike. A guest's opening is silent: it goes into the log without a sound,
	// because sound belongs to the owner's own actions.
	guestInit := info != nil && info.GuestOID != 0
	var keyID int64
	if guestInit {
		keyID = info.UserKeyID
	}
	if h := hub.host(c.snapHostID()); h != nil {
		out := map[string]any{"type": "device_status", "call_id": commandID,
			"device_id": c.snapDeviceID(), "number_id": numberID, "level": level,
			"message": message, "final": final, "user_key_id": keyID,
			// Sound belongs to the owner's own presses: a guest or the board
			// itself goes into the log quietly.
			"silent": guestInit || event != ""}
		if event != "" {
			out["event"] = event
		}
		if info != nil && info.Action != "" {
			out["action"] = info.Action
		}
		h.send(out)
	}
	if info != nil && info.UserKeyID > 0 {
		exec(`INSERT INTO call_log (user_key_id, number_id, ts, status) VALUES (?, ?, NOW(), ?)`,
			info.UserKeyID, info.NumberID, "dev_"+level)
	}

	// Firmware for a bistable object reports the position here.
	if pos := str(msg, "position"); validPosition(pos) {
		var nid, hid int64
		if err := queryRow(`SELECT id, host_id FROM numbers WHERE device_id = ? AND type = 'device'`,
			c.snapDeviceID()).Scan(&nid, &hid); err == nil {
			// A reply to a command or the board's own event (button, limit
			// switch, auto-close) is a real movement: no five-second limit,
			// or a close right after an open never reaches the phones. Only
			// the periodic heartbeat is throttled.
			if info != nil || event != "" {
				applyCommandState(hid, nid, pos)
			} else {
				applyObjectState(hid, nid, pos)
			}
		}
	}

	if final && info != nil {
		hub.dropCall(commandID)
	}
}

func webhookResult(c *Conn, msg map[string]any) {
	if c.snapRole() != "host" {
		return
	}
	callID := str(msg, "call_id")
	message := str(msg, "message")
	level := str(msg, "level")
	switch level {
	case "success", "warning", "danger", "info":
	default:
		if str(msg, "status") == "ok" {
			level = "success"
		} else {
			level = "danger"
		}
	}
	info := hub.call(callID)
	if info == nil {
		return
	}
	if g := hub.guest(info.GuestOID); g != nil {
		g.send(map[string]any{"type": "device_status", "call_id": callID,
			"level": level, "message": message, "final": true})
	}
	if info.UserKeyID > 0 {
		exec(`INSERT INTO call_log (user_key_id, number_id, ts, status) VALUES (?, ?, NOW(), ?)`,
			info.UserKeyID, info.NumberID, "webhook_"+level)
	}
	if pos := str(msg, "position"); validPosition(pos) {
		applyCommandState(c.snapHostID(), info.NumberID, pos)
	}
	hub.dropCall(callID)
}

// ── Pictures of objects ─────────────────────────────────────────────────────

func avatarRequest(c *Conn, msg map[string]any) {
	if c.snapRole() != "guest" {
		return
	}
	numberID := num(msg, "number_id")
	if numberID == 0 {
		return
	}
	h := hub.host(c.snapHostID())
	if h == nil {
		c.send(map[string]any{"type": "avatar_data", "number_id": numberID, "data": nil})
		return
	}
	h.send(map[string]any{"type": "avatar_request", "number_id": numberID, "guest_oid": c.id})
}

func avatarData(c *Conn, msg map[string]any) {
	if c.snapRole() != "host" {
		return
	}
	numberID := num(msg, "number_id")
	if numberID == 0 {
		return
	}
	g := hub.guest(num(msg, "guest_oid"))
	if g == nil {
		return
	}
	payload := map[string]any{"type": "avatar_data", "number_id": numberID}
	if cipher := str(msg, "avatar_cipher"); cipher != "" {
		payload["avatar_cipher"] = cipher
	} else {
		payload["data"] = str(msg, "data")
	}
	g.send(payload)
}

// ── Bluetooth ───────────────────────────────────────────────────────────────
//
// The server only routes here. The meaningful payload — the token, the
// signatures, the guest key — travels the other way and means nothing to it.

func bleTokenRenew(c *Conn, msg map[string]any) {
	if c.snapRole() != "guest" {
		return
	}
	bleID := num(msg, "ble_id")
	if bleID == 0 {
		return
	}
	hostID := c.snapHostID()
	req := map[string]any{
		"type": "ble_token_renew", "ble_id": bleID,
		"user_key_id": c.snapUserKeyID(), "guest_oid": c.id,
	}
	h := hub.host(hostID)
	if h == nil {
		// The owner is away: the request waits in the queue instead of being lost,
		// and the guest is told so rather than left watching a token ripen.
		enqueueHostMsg(hostID, req)
		c.send(map[string]any{"type": "ble_token_response",
			"ble_id": bleID, "error": "host_offline_queued"})
		return
	}
	h.send(req)
}

func bleTokenResponse(c *Conn, msg map[string]any) {
	if c.snapRole() != "host" {
		return
	}
	bleID := num(msg, "ble_id")
	g := hub.guest(num(msg, "guest_oid"))
	if g == nil {
		return
	}
	payload := map[string]any{"type": "ble_token_response", "ble_id": bleID}
	for _, k := range []string{"token", "sig", "gkey", "valid_until", "did", "label", "rssi", "error"} {
		if v, ok := msg[k]; ok {
			payload[k] = v
		}
	}
	g.send(payload)
}

func bleFireEvent(c *Conn, msg map[string]any) {
	if c.snapRole() != "guest" {
		return
	}
	items, ok := msg["items"].([]any)
	if !ok || len(items) == 0 {
		return
	}
	payload := map[string]any{
		"type": "ble_fire_event", "user_key_id": c.snapUserKeyID(), "items": items,
	}
	hostID := c.snapHostID()
	if h := hub.host(hostID); h != nil {
		h.send(payload)
	} else {
		enqueueHostMsg(hostID, payload)
	}
	// Either way these openings are accounted for: delivered, or safely queued.
	acked := []int64{}
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			if ts := num(m, "ts"); ts != 0 {
				acked = append(acked, ts)
			}
		}
	}
	c.send(map[string]any{"type": "ble_fire_event_ack", "acked_ts": acked})
}
