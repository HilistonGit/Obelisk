package probe

import (
	"context"
	"errors"
	"net"
	"net/http"
	neturl "net/url"
	"sort"
	"sync"
	"time"
)

// Health answers the two questions a user actually has, and keeps them apart.
//
// "Is the internet working" and "is the VPN working" are different questions
// with different right answers, and a single check cannot serve both. Reaching
// google.com proves neither: from a censored network it may fail while the
// connection is perfectly healthy, and it may succeed through a tunnel while the
// direct path is broken.
//
// So Internet is measured against sites that are never blocked and are hosted
// close by, where a failure means the line is genuinely down. Tunnel is measured
// against sites that are definitely blocked, where success is only possible if
// the traffic really left through the tunnel — which is the only honest proof
// that a VPN is doing anything at all.
type Health struct {
	Internet []Reach `json:"internet"`
	Tunnel   []Reach `json:"tunnel"`

	// InternetOK and TunnelOK are true when any target in that group answered.
	// Any rather than all: one site being down is that site's problem.
	InternetOK bool `json:"internet_ok"`
	TunnelOK   bool `json:"tunnel_ok"`

	CheckedAt time.Time `json:"checked_at"`
}

// Reach is one target's result.
type Reach struct {
	Host   string `json:"host"`
	OK     bool   `json:"ok"`
	Status int    `json:"status,omitempty"`
	Millis int    `json:"ms,omitempty"`
	Error  string `json:"error,omitempty"`
}

// DefaultInternetTargets are hosts that are not blocked in the networks Obelisk
// is built for, so that a failure means the connection itself is down rather
// than that somebody censored the probe.
var DefaultInternetTargets = []string{
	"https://yandex.ru/",
	"https://mail.ru/",
	"https://2ip.ru/",
}

// DefaultTunnelTargets are hosts that are blocked, so that reaching one is proof
// the traffic left through the tunnel rather than around it.
var DefaultTunnelTargets = []string{
	"https://telegram.org/",
	"https://rutracker.net/",
	"https://meduza.io/",
}

// CheckHealth probes both groups concurrently.
//
// dialProxy, when not nil, is used for the tunnel group: it is what makes the
// second question answerable, because a target reached by the ordinary route
// would prove nothing about the tunnel.
func CheckHealth(ctx context.Context, internet, tunnel []string, dialProxy DialFunc, timeout time.Duration) Health {
	if len(internet) == 0 {
		internet = DefaultInternetTargets
	}
	if len(tunnel) == 0 {
		tunnel = DefaultTunnelTargets
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}

	out := Health{CheckedAt: time.Now()}
	var wg sync.WaitGroup
	var mu sync.Mutex

	probe := func(url string, dial DialFunc, into *[]Reach) {
		defer wg.Done()
		r := reach(ctx, url, dial, timeout)
		mu.Lock()
		*into = append(*into, r)
		mu.Unlock()
	}

	for _, u := range internet {
		wg.Add(1)
		go probe(u, nil, &out.Internet)
	}
	for _, u := range tunnel {
		wg.Add(1)
		go probe(u, dialProxy, &out.Tunnel)
	}
	wg.Wait()

	// Concurrent appends arrive in whatever order they finish; a list that
	// reorders itself on every refresh is unreadable.
	sort.Slice(out.Internet, func(i, j int) bool { return out.Internet[i].Host < out.Internet[j].Host })
	sort.Slice(out.Tunnel, func(i, j int) bool { return out.Tunnel[i].Host < out.Tunnel[j].Host })

	for _, r := range out.Internet {
		out.InternetOK = out.InternetOK || r.OK
	}
	for _, r := range out.Tunnel {
		out.TunnelOK = out.TunnelOK || r.OK
	}
	return out
}

// DialFunc opens a connection, normally through a proxy.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// reach fetches one target and reports what happened.
func reach(ctx context.Context, url string, dial DialFunc, timeout time.Duration) Reach {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	r := Reach{Host: hostOf(url)}

	transport := &http.Transport{
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
	}
	if dial != nil {
		transport.DialContext = dial
	}
	client := &http.Client{
		Transport: transport,
		// Redirects are noise here. The question is whether the host answered
		// at all, and a 301 answers it.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	resp, err := client.Do(req)
	r.Millis = int(time.Since(start).Milliseconds())
	if err != nil {
		r.Error = shortError(err)
		return r
	}
	defer resp.Body.Close()

	r.Status = resp.StatusCode
	// Any answer from the server counts, including 403. A challenge page proves
	// the connection arrived, which is the whole question; whether the site then
	// likes the client is a different one.
	r.OK = resp.StatusCode > 0
	return r
}

func hostOf(raw string) string {
	if u, err := neturl.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// shortError trims Go's layered network errors to the part a user can act on.
func shortError(err error) string {
	msg := err.Error()
	if len(msg) > 140 {
		msg = msg[:140] + "…"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timed out"
	}
	return msg
}
