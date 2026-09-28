// The websocket worker.
//
// It holds the live connections of owners' phones, guests' phones and
// controllers, and relays between them. It is a relay and not a participant:
// what opens a gate travels through it signed by someone else, and the worker
// can neither read it nor produce it.
//
// This is a port of w/server.php, message for message. The protocol it speaks
// is the one described in spec/GUEST-PROTOCOL.md.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coder/websocket"
	_ "github.com/go-sql-driver/mysql"
)

var (
	cfg    Config
	db     *sql.DB
	hub    = newHub()
	connID atomic.Int64
)

func main() {
	// The watchdog line and the rest belong in the ordinary log, not in the
	// error stream: supervisor keeps the two apart, and a reader looking for a
	// failure should not have to wade through a heartbeat.
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags)

	cfg = loadConfig()

	var err error
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s?charset=utf8mb4&parseTime=false&loc=Local&timeout=5s",
		cfg.DBUser, cfg.DBPass, cfg.DBHost, cfg.DBName)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)
	db.SetConnMaxLifetime(time.Hour)
	if err := db.Ping(); err != nil {
		log.Fatalf("database unreachable: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	startTimers(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/", serveWS)
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()

	// Said once, at start, because it is the one setting whose default is a
	// decision: a server with no code lets anyone who knows the address put a
	// device on it. Nothing leaks — what opens gates never reaches the server —
	// but the owner should know which of the two servers they are running.
	if os.Getenv("ACCESS_CODE") == "" && cfg.AccessCode == "" {
		log.Printf("this server is open: anyone who knows the address can register a device. " +
			"To close it, set ACCESS_CODE or hand out invitations (entrixy-invites add)")
	}

	log.Printf("entrixy-ws listening on %s", cfg.Addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
		os.Exit(1)
	}
}

func serveWS(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// The page at /key and the app both come from another origin, and the
		// greeting is what authenticates a client here, not the origin header.
		InsecureSkipVerify: true,
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	ws.SetReadLimit(1 << 20) // a megabyte: ble_fire_event batches are the largest

	c := &Conn{
		id:       connID.Add(1),
		ws:       ws,
		out:      make(chan []byte, 64),
		closed:   make(chan struct{}),
		lastPong: time.Now(),
	}

	ctx := context.Background()
	go c.writeLoop(ctx)
	readLoop(ctx, c)
	onClose(c)
}

func readLoop(ctx context.Context, c *Conn) {
	defer c.close()
	for {
		typ, data, err := c.ws.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			continue
		}
		// One message must not be able to take a connection down silently: a
		// panic inside a handler is logged and answered, and the connection
		// lives on.
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("handler: %v", r)
					c.send(map[string]any{"type": "error", "reason": "server_error"})
				}
			}()
			handleMessage(c, data)
		}()
		select {
		case <-c.closed:
			return
		default:
		}
	}
}

func onClose(c *Conn) {
	role := c.snapRole()
	hostID := c.snapHostID()
	switch role {
	case "host":
		hub.mu.Lock()
		if hub.hosts[hostID] == c {
			delete(hub.hosts, hostID)
		}
		hub.mu.Unlock()
		exec(`UPDATE hosts SET last_seen = NOW() WHERE id = ?`, hostID)
		now := time.Now().Format("2006-01-02 15:04:05")
		for _, g := range hub.guestsOfHost(hostID) {
			g.send(map[string]any{"type": "host_status", "online": false, "last_seen": now})
		}
	case "guest":
		hub.mu.Lock()
		delete(hub.guests, c.id)
		hub.mu.Unlock()
	case "device":
		devID := c.snapDeviceID()
		hub.mu.Lock()
		if hub.devices[devID] == c {
			delete(hub.devices, devID)
		}
		hub.mu.Unlock()
		exec(`UPDATE devices SET last_seen = NOW() WHERE id = ?`, devID)
		msg, _ := json.Marshal(map[string]any{
			"type": "device_online", "device_id": devID, "online": false,
		})
		if h := hub.host(hostID); h != nil {
			h.sendRaw(msg)
		}
		for _, g := range hub.guestsOfHost(hostID) {
			g.sendRaw(msg)
		}
	}
}
