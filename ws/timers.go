package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"
)

// The periodic work, one goroutine each. The intervals are the ones the
// clients expect.
func startTimers(ctx context.Context) {
	go every(ctx, 30*time.Second, evictMovedOwners)
	go every(ctx, time.Second, pumpPendingActions)
	go every(ctx, time.Second, pumpNotifications)
	// Banners are ours alone: a server standing on its own has no such table,
	// and there is nothing to ask it for.
	if tableExists("promo") {
		go every(ctx, 5*time.Second, pumpPromo)
	}
	go every(ctx, time.Hour, expireMessages)
	go every(ctx, time.Hour, expireNonces)
	go every(ctx, 10*time.Second, pingPhones)
	go every(ctx, 30*time.Second, reapDevices)
}

func tableExists(name string) bool {
	var n int
	err := queryRow(`SELECT COUNT(*) FROM information_schema.tables
	                 WHERE table_schema = DATABASE() AND table_name = ?`, name).Scan(&n)
	return err == nil && n > 0
}

func every(ctx context.Context, d time.Duration, fn func()) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("timer: %v", r)
					}
				}()
				fn()
			}()
		}
	}
}

// Moving to a new phone. The old handset can sit on a connection for hours
// asking nothing, so twice a minute the fingerprints of connected owners are
// compared with what the database says and the ones that no longer match are
// evicted. Every connection is walked rather than the table: after a backup is
// restored two phones share one owner, and the table remembers only the later.
func evictMovedOwners() {
	bound := map[int64]string{}
	var detail []string
	hub.mu.RLock()
	conns := make([]*Conn, 0, len(hub.hosts))
	for _, c := range hub.hosts {
		conns = append(conns, c)
	}
	hub.mu.RUnlock()

	for _, c := range conns {
		hid := c.snapHostID()
		fp := c.snapFP()
		if fp == "" {
			detail = append(detail, itoa(hid)+":no-fingerprint")
			continue
		}
		detail = append(detail, itoa(hid)+":"+first(fp, 8))
		if _, seen := bound[hid]; !seen {
			var b sql.NullString
			queryRow(`SELECT bound_device_fp FROM hosts WHERE id = ?`, hid).Scan(&b)
			bound[hid] = b.String
		}
		if bound[hid] != "" && bound[hid] != fp {
			log.Printf("evicted host %d: fingerprint %.10s is no longer the owner", hid, fp)
			c.sendThenClose(map[string]any{"type": "evicted"})
		}
	}
	log.Printf("watchdog: hosts %d, guests %d, controllers %d — %s",
		len(conns), hubLen(hub.guests), hubLen(hub.devices), strings.Join(detail, ", "))
}

func hubLen[T any](m map[int64]T) int {
	hub.mu.RLock()
	defer hub.mu.RUnlock()
	return len(m)
}

// Openings asked for over the API rather than over a live connection: a
// company calling in, or a guest whose websocket is down.
func pumpPendingActions() {
	rows, ok := query(`SELECT pa.id, pa.host_id, pa.number_id, pa.user_key_id, pa.source, pa.actor,
	                          o.name AS org_name
	                   FROM pending_actions pa
	                   LEFT JOIN user_keys uk ON uk.id = pa.user_key_id
	                   LEFT JOIN orgs o ON o.id = uk.org_id
	                   WHERE pa.created_at > DATE_SUB(NOW(), INTERVAL 30 SECOND)
	                   ORDER BY pa.id ASC LIMIT 50`)
	if !ok {
		return
	}
	type action struct {
		id, hostID, numberID, userKeyID int64
		source, actor, orgName          sql.NullString
	}
	var list []action
	for rows.Next() {
		var a action
		if rows.Scan(&a.id, &a.hostID, &a.numberID, &a.userKeyID, &a.source, &a.actor, &a.orgName) == nil {
			list = append(list, a)
		}
	}
	rows.Close()

	for _, a := range list {
		exec(`DELETE FROM pending_actions WHERE id = ?`, a.id)
		h := hub.host(a.hostID)
		if h == nil {
			continue
		}
		callID := newCallID()
		hub.putCall(callID, &Call{UserKeyID: a.userKeyID, NumberID: a.numberID, HostID: a.hostID})
		// An opening by a company is labelled with its name and its employee:
		// "org_api" tells the owner nothing.
		isOrg := a.orgName.Valid && a.orgName.String != ""
		label := a.source.String
		org := 0
		if isOrg {
			label = a.orgName.String
			org = 1
		}
		h.send(map[string]any{"type": "do_call", "call_id": callID,
			"number_id": a.numberID, "user_key_id": a.userKeyID,
			"guest_label": label, "org": org, "actor": a.actor.String})
	}
	exec(`DELETE FROM pending_actions WHERE created_at < DATE_SUB(NOW(), INTERVAL 5 MINUTE)`)
}

// News the API left for whoever is connected: a key revoked, a mode changed, a
// message read, access passed on, a key's objects edited.
func pumpNotifications() {
	rows, ok := query(`SELECT id, kind, user_key_id FROM pending_notifications
	                   WHERE created_at > DATE_SUB(NOW(), INTERVAL 60 SECOND)
	                   ORDER BY id ASC LIMIT 100`)
	if !ok {
		return
	}
	type note struct {
		id, keyID int64
		kind      string
	}
	var list []note
	for rows.Next() {
		var n note
		if rows.Scan(&n.id, &n.kind, &n.keyID) == nil {
			list = append(list, n)
		}
	}
	rows.Close()

	for _, n := range list {
		exec(`DELETE FROM pending_notifications WHERE id = ?`, n.id)
		switch n.kind {
		case "key_revoked":
			for _, g := range hub.guestsOfKey(n.keyID) {
				g.sendThenClose(map[string]any{"type": "error", "reason": "bad_key"})
			}
		case "key_mode_changed":
			var mode sql.NullString
			queryRow(`SELECT mode FROM user_keys WHERE id = ?`, n.keyID).Scan(&mode)
			newMode := mode.String
			if newMode == "" {
				newMode = "auto"
			}
			for _, g := range hub.guestsOfKey(n.keyID) {
				g.mu.Lock()
				g.keyMode = newMode
				g.mu.Unlock()
				g.send(map[string]any{"type": "mode_update", "mode": newMode})
			}
		case "message_read", "message_delivered":
			var hostID int64
			if queryRow(`SELECT host_id FROM user_keys WHERE id = ?`, n.keyID).Scan(&hostID) == nil {
				if h := hub.host(hostID); h != nil {
					h.send(map[string]any{"type": n.kind, "user_key_id": n.keyID})
				}
			}
		case "key_delegated":
			// The guest passed access on. For the owner this is both news and work:
			// only they can assemble the bundle for the new key.
			var hostID int64
			var parent sql.NullInt64
			if queryRow(`SELECT host_id, parent_key_id FROM user_keys WHERE id = ?`, n.keyID).
				Scan(&hostID, &parent) == nil {
				if h := hub.host(hostID); h != nil {
					h.send(map[string]any{"type": "key_delegated",
						"user_key_id": n.keyID, "parent_key_id": parent.Int64})
				}
			}
		case "pass_open":
			notifyPassOpen(n.keyID)
		case "message_new":
			for _, g := range hub.guestsOfKey(n.keyID) {
				deliverMessages(g, n.keyID)
			}
		case "key_updated":
			for _, g := range hub.guestsOfKey(n.keyID) {
				g.send(map[string]any{"type": "numbers_update", "numbers": keyNumbers(n.keyID, g.snapApp())})
			}
		}
	}
	exec(`DELETE FROM pending_notifications WHERE created_at < DATE_SUB(NOW(), INTERVAL 5 MINUTE)`)
}

func pumpPromo() {
	var (
		id                               int64
		typ, icon, banner, title, body   sql.NullString
		btnText, btnURL, bg, fg, display sql.NullString
		targetLang                       sql.NullString
		ttl, heightDP                    sql.NullInt64
	)
	err := queryRow(`SELECT id, type, icon_url, banner_url, title, body, button_text, button_url,
	                        bg_color, text_color, display_mode, target_lang,
	                        cache_ttl_seconds, height_dp
	                 FROM promo WHERE enabled = 1 AND push_pending = 1 LIMIT 1`).
		Scan(&id, &typ, &icon, &banner, &title, &body, &btnText, &btnURL,
			&bg, &fg, &display, &targetLang, &ttl, &heightDP)
	if err != nil {
		return
	}
	exec(`UPDATE promo SET push_pending = 0 WHERE id = ?`, id)

	abs := func(v sql.NullString) any {
		if !v.Valid || v.String == "" {
			return nil
		}
		return cfg.PromoBase + v.String
	}
	payload, _ := json.Marshal(map[string]any{
		"type": "promo_update",
		"promo": map[string]any{
			"id": id, "type": typ.String,
			"icon_url": abs(icon), "banner_url": abs(banner),
			"title": title.String, "body": body.String,
			"button_text": btnText.String, "button_url": btnURL.String,
			"bg_color": bg.String, "text_color": nullOrString(fg),
			"display_mode": display.String,
			"cache_ttl":    ttl.Int64, "height_dp": heightDP.Int64,
		},
	})
	for _, c := range hub.allPhones() {
		// A promo aimed at one language skips clients known to speak another.
		if targetLang.String != "" && c.snapLang() != "" && c.snapLang() != targetLang.String {
			continue
		}
		c.sendRaw(payload)
	}
}

func nullOrString(v sql.NullString) any {
	if !v.Valid {
		return nil
	}
	return v.String
}

// Messages live a week. Owners who are online are told before the deletion, so
// the interface shows "not delivered" instead of a stuck "sent".
func expireMessages() {
	rows, ok := query(`SELECT host_id, user_key_id FROM guest_messages
	                   WHERE created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)`)
	if !ok {
		return
	}
	for rows.Next() {
		var hostID, keyID int64
		if rows.Scan(&hostID, &keyID) != nil {
			continue
		}
		if h := hub.host(hostID); h != nil {
			h.send(map[string]any{"type": "message_expired", "user_key_id": keyID})
		}
	}
	rows.Close()
	exec(`DELETE FROM guest_messages WHERE created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)`)
}

// A used number is refused for as long as a signature could still be inside
// its five-minute window. A day is kept, far past that, and the rest goes:
// without this the table grows by a row per greeting and never shrinks.
func expireNonces() {
	exec(`DELETE FROM guest_nonces WHERE used_at < DATE_SUB(NOW(), INTERVAL 1 DAY)`)
}

// Phones are pinged every ten seconds and the silent are reaped after twenty:
// there are few of them and presence should be quick.
func pingPhones() {
	for _, c := range hub.allPhones() {
		if c.silentFor() > 20*time.Second {
			c.close()
			continue
		}
		c.send(map[string]any{"type": "ping"})
	}
}

// Controllers are not pinged: a fan-out to tens of thousands of boards does not
// scale. A board reports in by itself and here we only close the silent.
func reapDevices() {
	for _, d := range hub.allDevices() {
		if d.silentFor() > 90*time.Second {
			d.close()
		}
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func first(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
