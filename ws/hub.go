package main

import (
	"context"
	"encoding/json"
	"sync"
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
}

func (c *Conn) send(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	c.sendRaw(b)
}

func (c *Conn) sendRaw(b []byte) {
	select {
	case c.out <- b:
	case <-c.closed:
	default:
		// The reader on the other end has stopped taking messages and the queue is
		// full: the connection is dead in all but name, so it is dropped rather
		// than allowed to hold memory.
		c.close()
	}
}

// Close after the frame currently queued has gone out. The phones rely on
// this: an "evicted" that never arrives leaves the old handset thinking it is
// still the owner.
func (c *Conn) sendThenClose(v any) {
	c.send(v)
	go func() {
		time.Sleep(300 * time.Millisecond)
		c.close()
	}()
}

func (c *Conn) close() {
	c.once.Do(func() {
		close(c.closed)
		c.ws.Close(websocket.StatusNormalClosure, "")
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
	}
}

func (h *Hub) host(id int64) *Conn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.hosts[id]
}

func (h *Hub) device(id int64) *Conn {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.devices[id]
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
	h.calls[id] = c
	h.mu.Unlock()
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
