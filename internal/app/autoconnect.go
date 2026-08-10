package app

import (
	"context"
	"log"
	"strconv"
	"time"
)

// autoConnectAttempts bounds how long the daemon keeps trying to bring the
// tunnel up on its own before leaving it to the user.
//
// The delays are deliberately front-loaded and then long: the common case on a
// router is that everything is ready within a few seconds, and the uncommon one
// is a PPPoE link that takes half a minute to dial. Past that, retrying is no
// longer useful — the problem is a bad subscription or an unreachable server,
// and those are fixed in the interface, not by waiting.
var autoConnectDelays = []time.Duration{
	0,
	3 * time.Second,
	7 * time.Second,
	15 * time.Second,
	30 * time.Second,
	60 * time.Second,
	120 * time.Second,
}

// AutoConnect brings the tunnel up at startup, retrying while the reason for
// failing looks temporary.
//
// The retry is the whole point. A router reboots, Obelisk starts as soon as
// Docker does, and at that moment the WAN may still be dialling: the first
// attempt fails because no route to the server exists yet. A single attempt
// would leave the tunnel down until somebody noticed and pressed a button,
// which is exactly the situation automatic connection exists to remove.
//
// It gives up the moment the user takes a decision of their own — connecting or
// disconnecting by hand — because continuing to retry after that would be
// Obelisk overriding a person, and a VPN that reconnects itself against the
// user's wishes is worse than one that never connects.
func (a *App) AutoConnect(ctx context.Context) {
	for attempt, delay := range autoConnectDelays {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}

		if a.userDecided() {
			log.Print("obelisk: auto-connect stopped, the connection was taken over by hand")
			return
		}
		if a.Status().Connected {
			return
		}

		err := a.Connect(ctx)
		if err == nil {
			log.Printf("obelisk: connected automatically%s", attemptSuffix(attempt))
			return
		}
		if attempt < len(autoConnectDelays)-1 {
			log.Printf("obelisk: auto-connect attempt %d failed (%v), trying again in %s",
				attempt+1, err, autoConnectDelays[attempt+1])
		} else {
			log.Printf("obelisk: auto-connect gave up after %d attempts: %v", attempt+1, err)
			log.Print("obelisk: the interface is up — connect from there once the cause is fixed")
		}
	}
}

// attemptSuffix names the attempt only when it was not the first, so the
// ordinary case logs one clean line.
func attemptSuffix(attempt int) string {
	if attempt == 0 {
		return ""
	}
	return " on attempt " + strconv.Itoa(attempt+1)
}

// userDecided reports whether a person has driven the connection since the
// daemon started. Auto-connect stands down when they have.
func (a *App) userDecided() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.manualIntent
}

// NoteUserIntent records that the connection was driven by hand. The API calls
// it on connect and disconnect; the automatic path deliberately does not.
func (a *App) NoteUserIntent() {
	a.mu.Lock()
	a.manualIntent = true
	a.mu.Unlock()
}

// AutoConnectEnabled reports the persisted setting.
func (a *App) AutoConnectEnabled() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg.Settings.AutoConnect
}
