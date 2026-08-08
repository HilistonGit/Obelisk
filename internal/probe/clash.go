// Package probe measures what the cores are actually doing: how fast each node
// answers, and how much traffic is moving.
//
// Both come from sing-box's Clash API rather than from anything Obelisk builds
// itself. That is a deliberate choice. The front core already knows every node,
// already has a connection pool to them, and already counts bytes; measuring
// latency by opening our own sockets would test a different path than the one
// traffic takes, and would report numbers that disagree with reality in exactly
// the cases that matter.
//
// Xray-carried nodes are covered too: from the front core's point of view they
// are ordinary SOCKS outbounds, so a delay test through one measures the whole
// chain — which is the number a user cares about.
package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// DefaultTestURL is the endpoint delay tests fetch. It answers 204 with no body
// from almost everywhere, which makes it a measurement of the path rather than
// of somebody's web server.
const DefaultTestURL = "http://www.gstatic.com/generate_204"

// Client talks to the Clash API that sing-box exposes.
type Client struct {
	// BaseURL is the external controller address, e.g. "http://127.0.0.1:24090".
	BaseURL string

	// Secret authenticates to the controller when one is configured.
	Secret string

	HTTP *http.Client
}

// NewClient builds a client for a controller address.
func NewClient(address, secret string) *Client {
	base := address
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	return &Client{
		BaseURL: strings.TrimSuffix(base, "/"),
		Secret:  secret,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(encoded))
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	if c.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.Secret)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("clash api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		// The controller reports a failed delay test as a body with a message,
		// which is far more useful to pass on than the status code alone.
		if message := clashMessage(payload); message != "" {
			return fmt.Errorf("%s", message)
		}
		return fmt.Errorf("clash api: HTTP %s", resp.Status)
	}

	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

// clashMessage extracts the error text from a controller response.
func clashMessage(payload []byte) string {
	var body struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return ""
	}
	if body.Message != "" {
		return body.Message
	}
	return body.Error
}

// Proxy is one outbound or group as the controller reports it.
type Proxy struct {
	Name    string         `json:"name"`
	Type    string         `json:"type"`
	Now     string         `json:"now,omitempty"`
	All     []string       `json:"all,omitempty"`
	History []DelaySample  `json:"history,omitempty"`
	UDP     bool           `json:"udp,omitempty"`
	Extra   map[string]any `json:"-"`
}

// DelaySample is one recorded latency measurement.
type DelaySample struct {
	Time  time.Time `json:"time"`
	Delay int       `json:"delay"`
}

// LastDelay returns the most recent measurement, or zero when there is none.
// A delay of zero from the controller means the test failed, not that the node
// is instant, so it is reported as unreachable rather than as a great result.
func (p Proxy) LastDelay() int {
	if len(p.History) == 0 {
		return 0
	}
	return p.History[len(p.History)-1].Delay
}

// Proxies lists every outbound and group the front core knows about.
func (c *Client) Proxies(ctx context.Context) (map[string]Proxy, error) {
	var body struct {
		Proxies map[string]Proxy `json:"proxies"`
	}
	if err := c.do(ctx, http.MethodGet, "/proxies", nil, &body); err != nil {
		return nil, err
	}
	for name, p := range body.Proxies {
		p.Name = name
		body.Proxies[name] = p
	}
	return body.Proxies, nil
}

// Delay measures how long the node takes to answer, in milliseconds.
func (c *Client) Delay(ctx context.Context, name, testURL string, timeout time.Duration) (int, error) {
	if testURL == "" {
		testURL = DefaultTestURL
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	query := url.Values{}
	query.Set("url", testURL)
	query.Set("timeout", fmt.Sprintf("%d", timeout.Milliseconds()))
	path := "/proxies/" + url.PathEscape(name) + "/delay?" + query.Encode()

	var body struct {
		Delay int `json:"delay"`
	}
	// The request needs longer than the test itself, or the client gives up
	// before the controller has finished deciding the node is unreachable.
	ctx, cancel := context.WithTimeout(ctx, timeout+5*time.Second)
	defer cancel()

	if err := c.do(ctx, http.MethodGet, path, nil, &body); err != nil {
		return 0, err
	}
	return body.Delay, nil
}

// Select points a selector group at one of its members.
func (c *Client) Select(ctx context.Context, group, member string) error {
	path := "/proxies/" + url.PathEscape(group)
	return c.do(ctx, http.MethodPut, path, map[string]string{"name": member}, nil)
}

// Snapshot is one reading of the counters.
type Snapshot struct {
	UploadTotal   int64     `json:"upload_total"`
	DownloadTotal int64     `json:"download_total"`
	Connections   int       `json:"connections"`
	Taken         time.Time `json:"taken"`

	// Flows is every live connection with the bytes it has carried and whether
	// it left through the tunnel.
	//
	// The per-connection figures cannot be summed into a counter: a connection
	// that closes takes its bytes out of the total, so the sum goes down and
	// differencing it would produce negative rates. The monitor instead follows
	// each identifier between samples and adds only its own increase, which is
	// the one form that survives connections coming and going.
	Flows []Flow `json:"-"`
}

// Flow is one live connection's contribution.
type Flow struct {
	ID      string
	Up      int64
	Down    int64
	Proxied bool
}

// Connections reads the cumulative counters and the live connection count.
//
// Polling this rather than holding the controller's streaming /traffic endpoint
// open is a deliberate simplification: one request yields the rates (by
// differencing), the session totals and the connection count at once, with no
// long-lived stream to keep alive, reconnect, or leak.
func (c *Client) Connections(ctx context.Context) (*Snapshot, error) {
	var body struct {
		UploadTotal   int64 `json:"uploadTotal"`
		DownloadTotal int64 `json:"downloadTotal"`
		Connections   []struct {
			ID       string   `json:"id"`
			Chains   []string `json:"chains"`
			Upload   int64    `json:"upload"`
			Download int64    `json:"download"`
		} `json:"connections"`
	}
	if err := c.do(ctx, http.MethodGet, "/connections", nil, &body); err != nil {
		return nil, err
	}

	flows := make([]Flow, 0, len(body.Connections))
	for _, conn := range body.Connections {
		// The chain reads outermost first; what actually carried the connection
		// is the last entry. Anything ending at the direct outbound never left
		// through the tunnel, however many rules it passed on the way.
		proxied := true
		if len(conn.Chains) > 0 && conn.Chains[len(conn.Chains)-1] == "direct" {
			proxied = false
		}
		flows = append(flows, Flow{ID: conn.ID, Up: conn.Upload, Down: conn.Download, Proxied: proxied})
	}

	return &Snapshot{
		UploadTotal:   body.UploadTotal,
		DownloadTotal: body.DownloadTotal,
		Connections:   len(body.Connections),
		Flows:         flows,
		Taken:         time.Now(),
	}, nil
}

// CloseConnections drops every active connection, which is how a node switch
// takes effect immediately instead of when the last long-lived stream ends.
func (c *Client) CloseConnections(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/connections", nil, nil)
}

// Version reports the core behind the controller, and doubles as a reachability
// check before anything else is attempted.
func (c *Client) Version(ctx context.Context) (string, error) {
	var body struct {
		Version string `json:"version"`
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := c.do(ctx, http.MethodGet, "/version", nil, &body); err != nil {
		return "", err
	}
	return body.Version, nil
}

// Device is one LAN client's share of what is going through the tunnel.
//
// Grouping live connections by where they came from rather than by protocol is
// the more useful cut on a router: the protocol is a property of the server
// currently selected, so at any moment nearly every connection has the same one
// and the breakdown says nothing. Which machine in the house is responsible for
// the traffic is a question the answer to which changes minute by minute.
type Device struct {
	IP          string `json:"ip"`
	Name        string `json:"name,omitempty"`
	Connections int    `json:"connections"`
	Up          int64  `json:"up"`
	Down        int64  `json:"down"`
}

// Destination is one remote host's share.
type Destination struct {
	Host        string `json:"host"`
	Connections int    `json:"connections"`
	Up          int64  `json:"up"`
	Down        int64  `json:"down"`

	// Proxied is how many of them went through the tunnel rather than direct,
	// which is what makes the row worth reading in a split tunnel.
	Proxied int `json:"proxied"`
}

// Live is the current connection table, summarized two ways.
type Live struct {
	Total        int           `json:"total"`
	Proxied      int           `json:"proxied"`
	Direct       int           `json:"direct"`
	Devices      []Device      `json:"devices"`
	Destinations []Destination `json:"destinations"`
}

// LiveConnections reads the connection table and summarizes it.
func (c *Client) LiveConnections(ctx context.Context, directTag string) (*Live, error) {
	var body struct {
		Connections []struct {
			Chains   []string `json:"chains"`
			Upload   int64    `json:"upload"`
			Download int64    `json:"download"`
			Metadata struct {
				SourceIP        string `json:"sourceIP"`
				Host            string `json:"host"`
				DestinationIP   string `json:"destinationIP"`
				DestinationPort string `json:"destinationPort"`
				Network         string `json:"network"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	if err := c.do(ctx, http.MethodGet, "/connections", nil, &body); err != nil {
		return nil, err
	}
	if directTag == "" {
		directTag = "direct"
	}

	out := &Live{Total: len(body.Connections)}
	devices := map[string]*Device{}
	dests := map[string]*Destination{}

	for _, conn := range body.Connections {
		// The chain is the outbound that carried it, innermost last. A
		// connection that ended at the direct outbound never left the router
		// through the tunnel, however many rules it passed on the way.
		proxied := true
		if len(conn.Chains) > 0 && conn.Chains[len(conn.Chains)-1] == directTag {
			proxied = false
		}
		if proxied {
			out.Proxied++
		} else {
			out.Direct++
		}

		src := conn.Metadata.SourceIP
		if src == "" {
			src = "router"
		}
		d, ok := devices[src]
		if !ok {
			d = &Device{IP: src}
			devices[src] = d
		}
		d.Connections++
		d.Up += conn.Upload
		d.Down += conn.Download

		host := conn.Metadata.Host
		if host == "" {
			host = conn.Metadata.DestinationIP
		}
		if host == "" {
			continue
		}
		t, ok := dests[host]
		if !ok {
			t = &Destination{Host: host}
			dests[host] = t
		}
		t.Connections++
		t.Up += conn.Upload
		t.Down += conn.Download
		if proxied {
			t.Proxied++
		}
	}

	for _, d := range devices {
		out.Devices = append(out.Devices, *d)
	}
	for _, t := range dests {
		out.Destinations = append(out.Destinations, *t)
	}

	// Busiest first, by bytes rather than by connection count: one download
	// matters more than fifty idle keep-alives, and the list is short.
	sort.Slice(out.Devices, func(i, j int) bool {
		a, b := out.Devices[i], out.Devices[j]
		if a.Down+a.Up != b.Down+b.Up {
			return a.Down+a.Up > b.Down+b.Up
		}
		return a.Connections > b.Connections
	})
	sort.Slice(out.Destinations, func(i, j int) bool {
		a, b := out.Destinations[i], out.Destinations[j]
		if a.Down+a.Up != b.Down+b.Up {
			return a.Down+a.Up > b.Down+b.Up
		}
		return a.Connections > b.Connections
	})
	return out, nil
}
