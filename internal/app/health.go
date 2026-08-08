package app

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/obelisk-project/obelisk/internal/probe"
	"golang.org/x/net/proxy"
)

// Health reports whether the internet works and whether the tunnel works, as
// two separate answers.
//
// They are separate because they fail separately and the remedies are opposite.
// A router whose line is down and a router whose tunnel is misrouted look
// identical from a browser, and the single "connected" light every VPN client
// shows is exactly the thing that cannot tell them apart — it reports that a
// process is running, not that traffic is arriving anywhere.
//
// The tunnel group is fetched through the core's own SOCKS listener rather than
// by the ordinary route. That is the whole point: a blocked host answering over
// the normal path would mean the block had lifted, not that the tunnel works.
func (a *App) Health(ctx context.Context) probe.Health {
	a.mu.RLock()
	internet := append([]string(nil), a.cfg.Settings.Health.Internet...)
	tunnel := append([]string(nil), a.cfg.Settings.Health.Tunnel...)
	socks := fmt.Sprintf("127.0.0.1:%d", a.singboxOptions().MixedPort)
	connected := a.connected
	a.mu.RUnlock()

	var dial probe.DialFunc
	if connected {
		dial = socksDialer(socks)
	}
	return probe.CheckHealth(ctx, internet, tunnel, dial, 8*time.Second)
}

// socksDialer routes a connection through the core's mixed inbound.
//
// Names are handed to the proxy unresolved. Resolving them here would defeat
// the check twice over: the answer would come from this side of the tunnel, and
// for a host blocked by DNS there would be no answer at all.
func socksDialer(address string) probe.DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer, err := proxy.SOCKS5("tcp", address, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		if ctxDialer, ok := dialer.(proxy.ContextDialer); ok {
			return ctxDialer.DialContext(ctx, network, addr)
		}
		return dialer.Dial(network, addr)
	}
}
