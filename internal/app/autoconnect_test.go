package app

import (
	"testing"

	"github.com/obelisk-project/obelisk/internal/config"
)

// A person pressing disconnect has to win. Retrying after that would mean the
// client reconnecting a tunnel somebody just switched off, which is a worse
// failure than never connecting on its own: it is unexplainable from the
// outside and there is no way to stop it from the interface.
func TestManualIntentStopsAutoConnect(t *testing.T) {
	a := &App{cfg: &config.Config{}}

	if a.userDecided() {
		t.Fatal("nobody has touched it yet and it already thinks they have")
	}

	a.NoteUserIntent()

	if !a.userDecided() {
		t.Error("a manual connect or disconnect was not recorded, so the retry loop would fight the user")
	}
}

// The setting has to default to on. A router that reboots at 3am with nobody
// watching is the case automatic connection exists for; defaulting it off would
// make the feature something you have to know to look for.
func TestAutoConnectDefaultsOn(t *testing.T) {
	if !config.Default().Settings.AutoConnect {
		t.Error("auto-connect is off by default")
	}
}

// The setting is what survives a restart, so it has to round-trip through the
// file rather than living only in memory.
func TestAutoConnectPersists(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/obelisk.json"

	cfg := config.Default()
	cfg.Settings.AutoConnect = false
	if err := cfg.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if reloaded.Settings.AutoConnect {
		t.Error("auto-connect was switched off and came back on after a reload")
	}
}

// The backoff has to start immediately and then widen. Starting with a delay
// would leave the network down for no reason in the common case where
// everything is already up.
func TestAutoConnectBackoffShape(t *testing.T) {
	if len(autoConnectDelays) < 3 {
		t.Fatal("too few attempts to survive a WAN that takes a moment to dial")
	}
	if autoConnectDelays[0] != 0 {
		t.Errorf("the first attempt waits %s; it should be immediate", autoConnectDelays[0])
	}
	for i := 1; i < len(autoConnectDelays); i++ {
		if autoConnectDelays[i] <= autoConnectDelays[i-1] {
			t.Errorf("delay %d (%s) does not widen on %d (%s)",
				i, autoConnectDelays[i], i-1, autoConnectDelays[i-1])
		}
	}

	var total float64
	for _, d := range autoConnectDelays {
		total += d.Seconds()
	}
	// Long enough for a slow PPPoE dial, short enough that a genuinely broken
	// configuration stops being retried and starts being reported.
	if total < 60 || total > 600 {
		t.Errorf("the whole sequence spans %.0fs, which is outside what a boot delay can excuse", total)
	}
}
