package main

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

// One connected client: an owner's phone, a guest's phone or a controller.
//
// Everything written to a socket goes through out, so a single goroutine per
// connection does the writing and two messages can never interleave. The fields
// below are set once at the greeting and read from the hub afterwards.
type Conn struct {
	id     int64
	ws     *websocket.Conn
	out    chan []byte
	closed chan struct{}
	once   sync.Once

	mu         sync.Mutex
	role       string // host | guest | device
	hostID     int64
	userKeyID  int64
	deviceID   int64
	deviceFP   string
	clientLang string
	keyMode    string
	// The guest proved it is the app (attestation): objects marked "app
	// only" open for it, a browser client does not see them.
	appClient bool
	sockE2EE  bool
	lastPong  time.Time
	// Seconds of silence after which a controller is dropped: the server's
	// setting for firmware that takes its period from us, 90 for older
	// firmware that pings every 30 s on its own.
	offlineS int
	// Messages allowed right now (a token bucket, read loop only): a flood from
	// one connection must not fill the owner's queue and push the owner off.
	rateTokens float64
	rateAt     time.Time
	rateDrops  int
	selfWindow time.Time
	selfCount  int
	// Why the connection ended, for the log: the first cause set wins.
	reason string
	since  time.Time
	// A controller has reported its position on this connection already.
	posSeen bool
	// The connection was refused and is only waiting for its last frame to go
	// out: nothing it sends from now on is acted upon.
	closing atomic.Bool
	// The client's address, for pacing greetings: a stranger repeating someone
	// else's id must not use up that person's slot.
	ip string
}

func (c *Conn) setReason(r string) {
	c.mu.Lock()
	if c.reason == "" {
		c.reason = r
	}
	c.mu.Unlock()
}

func (c *Conn) send(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	c.sendRaw(b)
}

func (c *Conn) sendRaw(b []byte) { c.trySend(b) }

// sendWait queues a frame, waiting up to d for room: a stored queue handed
// over on a slow link must not overflow and drop the connection.
func (c *Conn) sendWait(b []byte, d time.Duration) bool {
	// Closed already: say so first. With room in the buffer select would pick
	// between the two ready cases at random and report half the frames as sent
	// into a connection that is gone.
	if c.isClosed() {
		return false
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case c.out <- b:
		return true
	case <-c.closed:
		return false
	case <-t.C:
		return false
	}
}

// trySend reports whether the frame was queued.
func (c *Conn) trySend(b []byte) bool {
	if c.isClosed() {
		return false
	}
	select {
	case c.out <- b:
		return true
	case <-c.closed:
		return false
	default:
		// The reader on the other end has stopped taking messages and the queue is
		// full: the connection is dead in all but name, so it is dropped rather
		// than allowed to hold memory.
		c.setReason("send queue full")
		c.close()
		return false
	}
}

// Close after the frame currently queued has gone out. The phones rely on
// this: an "evicted" that never arrives leaves the old handset thinking it is
// still the owner.
func (c *Conn) sendThenClose(v any) {
	c.send(v)                // the last frame first: closing below stops every later one
	c.closing.Store(true)
	go func() {
		time.Sleep(300 * time.Millisecond)
		c.close()
	}()
}

func (c *Conn) isClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return c.closing.Load()
	}
}

func (c *Conn) close() {
	c.once.Do(func() {
		close(c.closed)
		// Closing waits for the other side's answer, up to five seconds when it
		// is gone: the caller (a new connection replacing this one, the ping
		// timer going through every phone) must not wait with it.
		go c.ws.Close(websocket.StatusNormalClosure, "")
	})
}

func (c *Conn) touch() {
	c.mu.Lock()
	c.lastPong = time.Now()
	c.mu.Unlock()
}

func (c *Conn) silentFor() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.lastPong)
}

// An opening in flight. It lives from the moment a guest or an owner asks until
// a final answer comes back, and it is what lets a reply be matched to the
// request it belongs to — and refused when it does not.
type Call struct {
	GuestOID  int64
	HostOID   int64
	UserKeyID int64
	NumberID  int64
	HostID    int64
	DeviceID  int64
	// What a controller is asked to do: "open" or "close" (bistable). The
	// caller decides, by the position it knows; for an encrypted controller it
	// also signs that very action, so the server cannot swap it.
	Action string
	// The guest's signature of the press. The owner's phone carries out a call
	// or a webhook only when it matches, so it is passed on untouched: the
	// server cannot make one up.
	Press map[string]any
	// When the call was registered: one that never gets a final status is
	// swept after an hour.
	at time.Time
	confirmed bool // the owner already answered the confirm request
}

// Everyone currently connected. One lock guards the lot: the traffic here is a
// handful of messages per second, and a single lock is easier to reason about
// than four.
type Hub struct {
	mu      sync.RWMutex
	hosts   map[int64]*Conn // host_id  → owner's phone
	guests  map[int64]*Conn // conn id  → guest's phone
	devices map[int64]*Conn // device_id → controller
	calls   map[string]*Call

	helloMu   sync.Mutex
	lastHello map[string]time.Time

	stateMu   sync.Mutex
	lastState map[int64]time.Time
	// Every command-driven change of an object's position bumps its counter, so
	// a pending auto-close knows whether someone has pressed since.
	stateGen map[int64]int64
	// The guest whose press last moved a controller: the limit switch reports
	// the end of that movement later, with no command behind it, and the guest
	// should see it too ("Opened", "Did not open").
	lastPress map[int64]guestPress
}

type guestPress struct {
	guestOID int64
	keyID    int64 // the presser's key: the result finds them after a reconnect too
	numberID any
	at       time.Time
}

func newHub() *Hub {
	return &Hub{
		hosts:     map[int64]*Conn{},
		guests:    map[int64]*Conn{},
		devices:   map[int64]*Conn{},
		calls:     map[string]*Call{},
		lastHello: map[string]time.Time{},
		lastState: map[int64]time.Time{},
		stateGen:  map[int64]int64{},
		lastPress: map[int64]guestPress{},
	}
}

// A connection being closed is not the owner's any more: until its read loop
// ends it still sits in the map, and an opening handed to it would be lost.
func (h *Hub) host(id int64) *Conn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if c := h.hosts[id]; c != nil && !c.isClosed() {
		return c
	}
	return nil
}

func (h *Hub) device(id int64) *Conn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if c := h.devices[id]; c != nil && !c.isClosed() {
		return c
	}
	return nil
}

func (h *Hub) guest(id int64) *Conn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.guests[id]
}

// Every guest of one owner: used for the status of the owner, of a controller
// and for the state of an object.
func (h *Hub) guestsOfHost(hostID int64) []*Conn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []*Conn
	for _, g := range h.guests {
		if g.snapHostID() == hostID {
			out = append(out, g)
		}
	}
	return out
}

func (h *Hub) guestsOfKey(keyID int64) []*Conn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []*Conn
	for _, g := range h.guests {
		if g.snapUserKeyID() == keyID {
			out = append(out, g)
		}
	}
	return out
}

func (h *Hub) allPhones() []*Conn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*Conn, 0, len(h.hosts)+len(h.guests))
	for _, c := range h.hosts {
		out = append(out, c)
	}
	for _, c := range h.guests {
		out = append(out, c)
	}
	return out
}

func (h *Hub) allDevices() []*Conn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]*Conn, 0, len(h.devices))
	for _, c := range h.devices {
		out = append(out, c)
	}
	return out
}

func (h *Hub) putCall(id string, c *Call) {
	h.mu.Lock()
	if c.at.IsZero() {
		c.at = time.Now()
	}
	h.calls[id] = c
	h.mu.Unlock()
}

// Calls that never got a final status — a press the owner's phone refused, a
// challenge the guest never answered — would otherwise stay for good.
func expireCalls() {
	cut := time.Now().Add(-time.Hour)
	hub.mu.Lock()
	for id, c := range hub.calls {
		if c.at.Before(cut) {
			delete(hub.calls, id)
		}
	}
	hub.mu.Unlock()
}

// The owner's answer to a confirm request counts once: a repeated "allow"
// would send a second do_call (the phone refuses it, but the guest saw
// "dialing" turn into "declined").
func (h *Hub) takeConfirm(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := h.calls[id]
	if c == nil || c.confirmed {
		return false
	}
	c.confirmed = true
	return true
}

func (h *Hub) call(id string) *Call {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.calls[id]
}

func (h *Hub) dropCall(id string) {
	h.mu.Lock()
	delete(h.calls, id)
	h.mu.Unlock()
}

func (c *Conn) snapHostID() int64    { c.mu.Lock(); defer c.mu.Unlock(); return c.hostID }
func (c *Conn) snapUserKeyID() int64 { c.mu.Lock(); defer c.mu.Unlock(); return c.userKeyID }
func (c *Conn) snapRole() string     { c.mu.Lock(); defer c.mu.Unlock(); return c.role }
func (c *Conn) snapDeviceID() int64  { c.mu.Lock(); defer c.mu.Unlock(); return c.deviceID }
func (c *Conn) snapLang() string     { c.mu.Lock(); defer c.mu.Unlock(); return c.clientLang }
func (c *Conn) snapFP() string       { c.mu.Lock(); defer c.mu.Unlock(); return c.deviceFP }
func (c *Conn) snapApp() bool        { c.mu.Lock(); defer c.mu.Unlock(); return c.appClient }

// The writer. One per connection, and the only place a frame is written.
func (c *Conn) writeLoop(ctx context.Context) {
	for {
		select {
		case b := <-c.out:
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := c.ws.Write(wctx, websocket.MessageText, b)
			cancel()
			if err != nil {
				c.close()
				return
			}
		case <-c.closed:
			return
		case <-ctx.Done():
			return
		}
	}
}
