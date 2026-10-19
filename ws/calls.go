package main

import (
	"database/sql"
	"log"
	"sync"
	"time"
)

// selfOpenAllowed paces an owner opening their own objects through the server:
// twenty a minute is far beyond any hand, and keeps the server from becoming a
// source of requests to any address the owner names.
func selfOpenAllowed(c *Conn) bool {
	now := time.Now()
	if now.Sub(c.selfWindow) > time.Minute {
		c.selfWindow, c.selfCount = now, 0
	}
	c.selfCount++
	return c.selfCount <= 20
}

// The action for a controller: "close" only when asked for, anything else opens.
func deviceAction(msg map[string]any) string {
	if str(msg, "action") == "close" {
		return "close"
	}
	return "open"
}

// opening / closing: a controller with a limit switch between the pulse and
// the switch confirming.
func validPosition(p string) bool {
	switch p {
	case "open", "closed", "opening", "closing", "unknown":
		return true
	}
	return false
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
	// The key as it is now, not as it was at hello: a connection outlives an
	// expiry or a switch-off. No row — the key is gone.
	var live int
	if err := queryRow(`SELECT mode, force_when_busy,
	                           (enabled = 1 AND (expires_at IS NULL OR expires_at > NOW())) AS live
	                    FROM user_keys WHERE id = ?`, userKeyID).
		Scan(&mode, &forceBusy, &live); err != nil || live != 1 {
		c.send(map[string]any{"type": "error", "number_id": numberID, "reason": "disabled"})
		return
	}
	currentMode := mode.String
	if currentMode == "" {
		currentMode = "auto"
	}
	c.mu.Lock()
	c.keyMode = currentMode
	c.mu.Unlock()
	if currentMode == "off" || !ancestorsLive(userKeyID) {
		c.send(map[string]any{"type": "error", "number_id": numberID, "reason": "disabled"})
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
		c.send(map[string]any{"type": "error", "number_id": numberID, "reason": "forbidden"})
		return
	}
	// "App only" object: a browser client does not open it.
	if appOnly.Int64 == 1 && !c.snapApp() {
		c.send(map[string]any{"type": "error", "number_id": numberID, "reason": "native_only"})
		return
	}
	kind := objType.String
	if kind == "" {
		kind = "call"
	}
	// A Bluetooth lock is in the key's list but opens only next to it, from
	// the guest's own handset: there is nothing to send anywhere.
	if kind == "ble" {
		c.send(map[string]any{"type": "error", "number_id": numberID, "reason": "forbidden"})
		return
	}

	// Presses only: every opening also leaves dialing, busy and controller
	// lines, which would make the limit two or three times tighter. A count
	// that fails refuses, rather than lifting the limit.
	var recent int
	if queryRow(`SELECT COUNT(*) FROM call_log
	          WHERE user_key_id = ? AND status LIKE 'requested%'
	            AND ts > DATE_SUB(NOW(), INTERVAL 1 MINUTE)`, userKeyID).
		Scan(&recent) != nil || recent >= cfg.RateLimitPerMin {
		c.send(map[string]any{"type": "error", "number_id": numberID, "reason": "rate_limit"})
		return
	}

	callID := newCallID()
	press, _ := msg["press"].(map[string]any)
	hub.putCall(callID, &Call{
		GuestOID:  c.id,
		UserKeyID: userKeyID,
		NumberID:  numberID,
		// Whose call this is: only the owner of this object may confirm it, not
		// anyone who happens to hold an owner connection.
		HostID: hostID,
		Press:  press,
	})
	// The press is logged (and counted against the limit, and told up the chain)
	// only once it actually goes somewhere: a controller or an owner offline is
	// not an opening.
	pressed := func() {
		exec(`INSERT INTO call_log (user_key_id, number_id, ts, status) VALUES (?, ?, NOW(), ?)`,
			userKeyID, numberID, "requested")
		go notifyPassOpen(userKeyID)
	}

	switch {
	// ── A webhook fired by the server ──
	case kind == "webhook" && whMode.String == "server" && whURL.String != "":
		action, bistable := resolveWebhookAction(numberID, str(msg, "action"))
		pressed()
		fireWebhook(webhookJob{
			URL: whURL.String, Secret: whSecret.String,
			NumberID: numberID, CallID: callID, HostID: hostID,
			Requester: c, UserKeyID: userKeyID, NotifyHost: true,
			Action: action, Bistable: bistable,
		})
		c.send(map[string]any{"type": "call_status", "call_id": callID, "number_id": numberID, "status": "sending"})

	// ── A controller ──
	case kind == "device" && devIDCol.Valid && devIDCol.Int64 > 0:
		dev := hub.device(devIDCol.Int64)
		if dev == nil {
			c.send(map[string]any{"type": "error", "number_id": numberID, "reason": "device_offline"})
			hub.dropCall(callID)
			return
		}
		action := deviceAction(msg)
		pressed()
		if call := hub.call(callID); call != nil {
			hub.mu.Lock()
			call.DeviceID = devIDCol.Int64
			call.Action = action
			hub.mu.Unlock()
		}
		if dev.sockE2EE {
			// The controller is asked for a nonce. The guest signs it with their own
			// key and sends sock_fire; the server relays a signature it cannot
			// produce itself.
			dev.send(map[string]any{"type": "sock_challenge_req",
				"command_id": callID, "number_id": numberID})
			c.send(map[string]any{"type": "call_status", "call_id": callID, "number_id": numberID, "status": "challenge_pending"})
		} else {
			dev.send(map[string]any{"type": "device_command", "action": action,
				"command_id": callID, "number_id": numberID})
			c.send(map[string]any{"type": "call_status", "call_id": callID, "number_id": numberID, "status": "sent_to_device"})
		}
		if h := hub.host(hostID); h != nil {
			h.send(map[string]any{"type": "device_sent", "call_id": callID,
				"number_id": numberID, "user_key_id": userKeyID})
		}

	// ── A webhook fired by the owner's phone ──
	case kind == "webhook":
		h := hub.host(hostID)
		if h == nil {
			c.send(map[string]any{"type": "error", "number_id": numberID, "reason": "host_offline"})
			hub.dropCall(callID)
			return
		}
		pressed()
		// The owner's phone resolves "toggle" itself, by the position it holds.
		dw := map[string]any{"type": "do_webhook", "call_id": callID,
			"number_id": numberID, "user_key_id": userKeyID}
		if a := str(msg, "action"); a == "toggle" || a == "close" || a == "open" {
			dw["action"] = a
		}
		if press != nil {
			dw["press"] = press
		}
		h.send(dw)
		c.send(map[string]any{"type": "call_status", "call_id": callID, "number_id": numberID, "status": "sent_to_host"})

	// ── A phone call ──
	default:
		h := hub.host(hostID)
		if h == nil {
			c.send(map[string]any{"type": "error", "number_id": numberID, "reason": "host_offline"})
			hub.dropCall(callID)
			return
		}
		pressed()
		if currentMode == "confirm" {
			h.send(map[string]any{"type": "confirm_request", "call_id": callID,
				"number_id": numberID, "user_key_id": userKeyID, "press": press})
			c.send(map[string]any{"type": "call_status", "call_id": callID, "number_id": numberID, "status": "awaiting_confirm"})
		} else {
			h.send(map[string]any{"type": "do_call", "call_id": callID,
				"number_id": numberID, "user_key_id": userKeyID,
				"notify":          currentMode == "notify",
				"force_when_busy": forceBusy.Int64 == 1, "press": press})
			c.send(map[string]any{"type": "call_status", "call_id": callID, "number_id": numberID, "status": "requested"})
		}
	}
}

// ── The owner opens their own object ────────────────────────────────────────

func hostSelfWebhook(c *Conn, msg map[string]any) {
	if c.snapRole() != "host" {
		return
	}
	if !selfOpenAllowed(c) {
		c.send(map[string]any{"type": "error", "reason": "rate_limit"})
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
	action, bistable := resolveWebhookAction(numberID, str(msg, "action"))
	fireWebhook(webhookJob{
		URL: whURL.String, Secret: whSecret.String,
		NumberID: numberID, CallID: callID, HostID: hostID,
		Requester: c, UserKeyID: 0, NotifyHost: false,
		Action: action, Bistable: bistable,
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
	if !selfOpenAllowed(c) {
		c.send(map[string]any{"type": "error", "reason": "rate_limit"})
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
	action := deviceAction(msg)
	hub.putCall(callID, &Call{
		HostOID: c.id, NumberID: numberID, HostID: hostID, DeviceID: dev.Int64,
		Action: action,
	})
	if d.sockE2EE {
		d.send(map[string]any{"type": "sock_challenge_req",
			"command_id": callID, "number_id": numberID})
	} else {
		d.send(map[string]any{"type": "device_command", "action": action,
			"command_id": callID, "number_id": numberID})
	}
	c.send(map[string]any{"type": "device_sent", "call_id": callID, "number_id": numberID})
}

// How long an owner's "allow" still counts after the guest pressed.
const confirmMaxAge = 3 * time.Minute

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
	// An answer long after the press opens for nobody: the guest has gone. A
	// late "allow" is a refusal, and the guest is told so.
	hub.mu.Lock()
	age := time.Since(info.at)
	hub.mu.Unlock()
	if accept && age > confirmMaxAge {
		if hub.takeConfirm(callID) && guest != nil {
			guest.send(map[string]any{"type": "call_status", "call_id": callID, "number_id": info.NumberID, "status": "declined"})
		}
		c.send(map[string]any{"type": "confirm_expired", "call_id": callID})
		hub.dropCall(callID)
		return
	}
	if !hub.takeConfirm(callID) {
		return
	}
	if accept {
		c.send(map[string]any{"type": "do_call", "call_id": callID,
			"number_id": info.NumberID, "user_key_id": info.UserKeyID, "notify": false,
			"press": info.Press})
		if guest != nil {
			guest.send(map[string]any{"type": "call_status", "call_id": callID, "number_id": info.NumberID, "status": "accepted"})
		}
	} else {
		if guest != nil {
			guest.send(map[string]any{"type": "call_status", "call_id": callID, "number_id": info.NumberID, "status": "declined"})
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
	switch status {
	case "dialing", "busy", "declined", "error", "scheduled", "awaiting_confirm", "ended":
	default:
		return
	}
	info := hub.call(callID)
	// Only the owner the call went to answers it: another owner who learnt the
	// id (as a guest of this one) must not write its log or cancel it.
	if info == nil || info.HostID != c.snapHostID() {
		return
	}
	exec(`INSERT INTO call_log (user_key_id, number_id, ts, status) VALUES (?, ?, NOW(), ?)`,
		info.UserKeyID, info.NumberID, status)
	if g := hub.guest(info.GuestOID); g != nil {
		// With the object, as every other status: the guest may have pressed
		// another card since, and the answer belongs on this one.
		g.send(map[string]any{"type": "call_status", "call_id": callID, "number_id": info.NumberID, "status": status})
	}
	if status == "ended" || status == "error" || status == "declined" {
		hub.dropCall(callID)
	}
}

// ── The state of a bistable object ──────────────────────────────────────────

// Applies a new position with a diff, a rate limit and a broadcast. Returns
// true when the state really changed and the broadcast went out.
func applyObjectState(hostID, numID int64, position string) bool {
	return setObjectState(hostID, numID, position, false)
}

// The position that follows a command — somebody pressed open or close. It is
// not throttled: a close two seconds after an open is the point, not flapping.
func applyCommandState(hostID, numID int64, position string) bool {
	hub.stateMu.Lock()
	hub.stateGen[numID]++
	hub.stateMu.Unlock()
	return setObjectState(hostID, numID, position, true)
}

// A webhook reports its position only in the answer to a press; what happens
// afterwards nobody tells us. If the receiver named a time (close_in), the
// object is closed once it runs out. If not, after two seconds the position is
// unknown, and the next press of an open/close object opens again. Either way
// only if nobody has pressed in the meantime.
func scheduleWebhookForget(hostID, numID int64, position string, closeIn int) {
	delay, then := 2*time.Second, "unknown"
	if position == "open" && closeIn > 0 && closeIn <= 3600 {
		delay, then = time.Duration(closeIn)*time.Second, "closed"
	}
	hub.stateMu.Lock()
	gen := hub.stateGen[numID]
	hub.stateMu.Unlock()
	time.AfterFunc(delay, func() {
		hub.stateMu.Lock()
		same := hub.stateGen[numID] == gen
		hub.stateMu.Unlock()
		if same {
			applyCommandState(hostID, numID, then)
		}
	})
}

// What to send for a webhook. "toggle" is resolved here, by the position the
// server keeps for everyone: a phone may have missed somebody else's press.
// The second value tells whether the object is open/close rather than a pulse.
func resolveWebhookAction(numID int64, requested string) (string, bool) {
	switch requested {
	case "close":
		return "close", true
	// An explicit open comes only from an open/close object whose press was
	// automatic (geofence, Wi-Fi, time): open, and remember the position.
	case "open":
		return "open", true
	case "toggle":
		var last sql.NullString
		queryRow(`SELECT last_state FROM numbers WHERE id = ?`, numID).Scan(&last)
		if last.String == "open" {
			return "close", true
		}
		return "open", true
	}
	return "open", false
}

func setObjectState(hostID, numID int64, position string, force bool) bool {
	if !validPosition(position) {
		return false
	}
	var last sql.NullString
	var owner int64
	if err := queryRow(`SELECT last_state, host_id FROM numbers WHERE id = ?`, numID).
		Scan(&last, &owner); err != nil {
		return false
	}
	if owner != hostID {
		return false
	}
	if last.String == position {
		log.Printf("state %d: %s again, nothing to send", numID, position)
		return false
	}

	// One broadcast per five seconds per object, unless a command caused it.
	hub.stateMu.Lock()
	if !force && time.Since(hub.lastState[numID]) < 5*time.Second {
		hub.stateMu.Unlock()
		log.Printf("state %d: %s -> %s held back, a change less than 5 s ago", numID, last.String, position)
		return false
	}
	hub.lastState[numID] = time.Now()
	hub.stateMu.Unlock()

	log.Printf("state %d: %s -> %s (force=%v)", numID, last.String, position, force)
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
	if err != nil || len(b) > 64<<10 {
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

// One flush per owner at a time: the greeting and the timer would otherwise
// hand the same rows over twice.
var flushing sync.Map

func flushHostQueue(host *Conn, hostID int64) {
	if _, busy := flushing.LoadOrStore(hostID, true); busy {
		return
	}
	defer flushing.Delete(hostID)
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
	sent := 0
	for _, r := range list {
		if !host.sendWait([]byte(r.payload), 10*time.Second) {
			break // the rest waits for the next connection
		}
		exec(`DELETE FROM pending_host_msgs WHERE id = ?`, r.id)
		sent++
	}
	list = list[:sent]
	if len(list) > 0 {
		log.Printf("queue: %d message(s) handed to host %d", len(list), hostID)
	}
}

// notifyPassOpen tells everyone up the chain who passed this key on that it
// was used: their app then fetches the open into its journal. The owner learns
// of the open directly and is not in the chain.
func notifyPassOpen(userKeyID int64) {
	cur := userKeyID
	for i := 0; i < 50; i++ {
		var parent sql.NullInt64
		if queryRow(`SELECT parent_key_id FROM user_keys WHERE id = ?`, cur).Scan(&parent) != nil || !parent.Valid || parent.Int64 <= 0 {
			return
		}
		cur = parent.Int64
		for _, g := range hub.guestsOfKey(cur) {
			g.send(map[string]any{"type": "pass_open"})
		}
	}
}

// ancestorsLive: every key above this one is switched on, not paused and not
// expired. A key passed on lives only while the one it came through does.
func ancestorsLive(userKeyID int64) bool {
	id := userKeyID
	for i := 0; i < 50; i++ {
		var parent sql.NullInt64
		if queryRow(`SELECT parent_key_id FROM user_keys WHERE id = ?`, id).Scan(&parent) != nil {
			return false
		}
		if !parent.Valid || parent.Int64 == 0 {
			return true
		}
		id = parent.Int64
		var live int
		if queryRow(`SELECT (enabled = 1 AND COALESCE(mode, 'auto') <> 'off'
		                     AND (expires_at IS NULL OR expires_at > NOW()))
		             FROM user_keys WHERE id = ?`, id).Scan(&live) != nil || live != 1 {
			return false
		}
	}
	return false
}

// keySubtree: the key and every key passed on below it, nearest first.
func keySubtree(root int64) []int64 {
	out := []int64{root}
	seen := map[int64]bool{root: true}
	for i := 0; i < len(out) && len(out) < 1000; i++ {
		rows, ok := query(`SELECT id FROM user_keys WHERE parent_key_id = ?`, out[i])
		if !ok {
			break
		}
		for rows.Next() {
			var id int64
			if rows.Scan(&id) == nil && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
		rows.Close()
	}
	return out
}
