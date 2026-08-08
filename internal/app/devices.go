package app

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/obelisk-project/obelisk/internal/probe"
)

// leaseFiles are where a router keeps the names its DHCP server handed out.
//
// Reading them turns a list of addresses into a list of machines, which is the
// difference between "192.168.1.31 is using 340 KiB/s" and "the desktop is".
// The file is the router's, not Obelisk's, and is only ever read.
var leaseFiles = []string{
	"/host/dhcp.leases", // mounted into the container, where /tmp is its own
	"/tmp/dhcp.leases",  // OpenWrt, when running on the host
	"/var/lib/misc/dnsmasq.leases",
	"/var/lib/dhcp/dhcpd.leases",
}

// leaseCache holds the last parse. Leases change when a device joins the
// network, which is rarely, and re-reading the file on every request would put
// flash reads behind a panel that refreshes every few seconds.
type leaseCache struct {
	mu      sync.Mutex
	names   map[string]string
	read    time.Time
	sources string
}

var leases leaseCache

// deviceNames returns a map of address to hostname, refreshed at most once a
// minute. A missing file is not an error: plenty of routers hand out no names
// at all, and addresses on their own are still useful.
func deviceNames() map[string]string {
	leases.mu.Lock()
	defer leases.mu.Unlock()

	if leases.names != nil && time.Since(leases.read) < time.Minute {
		return leases.names
	}

	names := map[string]string{}
	var found []string
	for _, path := range leaseFiles {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		found = append(found, path)
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			// dnsmasq: <expiry> <mac> <address> <name> <client-id>
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 {
				continue
			}
			addr, name := fields[2], fields[3]
			if name == "*" || name == "" || addr == "" {
				continue
			}
			names[addr] = name
		}
		f.Close()
	}

	leases.names = names
	leases.read = time.Now()
	leases.sources = strings.Join(found, ", ")
	return names
}

// LiveConnections summarizes what is going through the tunnel right now, by
// which machine on the network is responsible and where it is going.
func (a *App) LiveConnections(ctx context.Context) (*probe.Live, error) {
	a.mu.RLock()
	opts := a.singboxOptions()
	connected := a.connected
	a.mu.RUnlock()

	if len(opts.TUNAddress) == 0 || !connected || opts.ClashAPIListen == "" {
		return &probe.Live{Devices: []probe.Device{}, Destinations: []probe.Destination{}}, nil
	}

	client := probe.NewClient(opts.ClashAPIListen, opts.ClashAPISecret)
	live, err := client.LiveConnections(ctx, "direct")
	if err != nil {
		return nil, fmt.Errorf("the core's control API did not answer: %w", err)
	}

	names := deviceNames()
	self := strings.SplitN(opts.TUNAddress[0], "/", 2)[0]
	for i := range live.Devices {
		switch {
		case live.Devices[i].IP == self || live.Devices[i].IP == "router":
			live.Devices[i].Name = "this router"
		default:
			if name, ok := names[live.Devices[i].IP]; ok {
				live.Devices[i].Name = name
			}
		}
	}
	if live.Devices == nil {
		live.Devices = []probe.Device{}
	}
	if live.Destinations == nil {
		live.Destinations = []probe.Destination{}
	}
	return live, nil
}

// HostInfo is what the box Obelisk runs on calls itself.
type HostInfo struct {
	OS     string  `json:"os,omitempty"`
	Uptime float64 `json:"uptime_seconds,omitempty"`
}

// Host reports the router's own identity and uptime, for the corner of the
// interface that says what this is running on.
//
// Both come from files the host shares read-only. In a container /proc/uptime
// is the host's, because the kernel is shared; the release file is not, so it
// is mounted in. Neither being available is unremarkable — Obelisk runs on
// plenty of systems that have neither — and the interface simply omits the line.
func (a *App) Host() HostInfo {
	info := HostInfo{}

	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		if secs, _, ok := strings.Cut(string(data), " "); ok {
			if v, err := parseFloat(secs); err == nil {
				info.Uptime = v
			}
		}
	}

	for _, path := range []string{"/host/os-release", "/etc/openwrt_release", "/host/openwrt_release", "/etc/os-release"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if name := releaseName(string(data)); name != "" {
			info.OS = name
			break
		}
	}
	return info
}

// releaseName pulls a human name out of an os-release or openwrt_release file,
// preferring the pretty form the distribution chose for itself.
func releaseName(text string) string {
	fields := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		fields[strings.TrimPrefix(key, "DISTRIB_")] = strings.Trim(value, "\"'")
	}
	if v := fields["DESCRIPTION"]; v != "" {
		return v
	}
	if v := fields["PRETTY_NAME"]; v != "" {
		return v
	}
	if name, release := fields["ID"], fields["RELEASE"]; name != "" {
		return strings.TrimSpace(name + " " + release)
	}
	return ""
}

func parseFloat(s string) (float64, error) {
	return strconv.ParseFloat(strings.TrimSpace(s), 64)
}
