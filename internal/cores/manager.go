package cores

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Installed describes a core binary present on disk.
type Installed struct {
	Kind        Kind      `json:"kind"`
	Target      string    `json:"target,omitempty"`
	Path        string    `json:"path"`
	Version     string    `json:"version"`
	SHA256      string    `json:"sha256,omitempty"`
	Size        int64     `json:"size,omitempty"`
	InstalledAt time.Time `json:"installed_at,omitempty"`
	AssetURL    string    `json:"asset_url,omitempty"`

	// Verified reports whether the publisher's own checksum was checked against
	// the download. False does not mean the binary is bad — sing-box publishes no
	// checksums at all — but it does mean the only guarantee is the TLS
	// connection it came over, and the UI says so rather than implying more.
	Verified bool `json:"verified"`

	// Managed distinguishes a binary Obelisk installed from one that was already
	// on the system. An unmanaged core is used but never replaced: on OpenWrt it
	// is likely opkg's, and overwriting a package manager's file is not Obelisk's
	// call to make.
	Managed bool `json:"managed"`
}

// Status is what the UI and CLI show for one core.
type Status struct {
	Kind            Kind       `json:"kind"`
	Installed       *Installed `json:"installed,omitempty"`
	Available       *Release   `json:"available,omitempty"`
	UpdateAvailable bool       `json:"update_available"`
	Error           string     `json:"error,omitempty"`
}

// UpdateResult reports what an update did.
type UpdateResult struct {
	Kind       Kind       `json:"kind"`
	Previous   *Installed `json:"previous,omitempty"`
	Current    *Installed `json:"current,omitempty"`
	Changed    bool       `json:"changed"`
	AlreadyNew bool       `json:"already_latest"`

	// Shadows is set when the installed copy takes precedence over a core that
	// was already on the system at this path.
	Shadows string `json:"shadows,omitempty"`
}

// Manager installs and updates cores under a single directory.
type Manager struct {
	// Dir holds the managed binaries, their backups and the state file. It must
	// be on a writable filesystem with room for two copies of each core.
	Dir string

	// Source resolves releases; the zero value queries GitHub anonymously.
	Source *Source

	// Client downloads assets. Downloads are large and slow compared with the
	// API calls, so they get their own client and their own timeout.
	Client *http.Client

	// ExtraLookupPaths are searched for a pre-existing core before falling back
	// to PATH, letting Obelisk adopt a binary installed by opkg.
	ExtraLookupPaths []string
}

func (m *Manager) client() *http.Client {
	if m.Client != nil {
		return m.Client
	}
	return &http.Client{Timeout: 15 * time.Minute}
}

func (m *Manager) source() *Source {
	if m.Source != nil {
		return m.Source
	}
	return &Source{}
}

// binaryPath returns where a managed core lives.
func (m *Manager) binaryPath(k Kind) string {
	return filepath.Join(m.Dir, k.BinaryName())
}

func (m *Manager) backupPath(k Kind) string {
	return m.binaryPath(k) + ".bak"
}

func (m *Manager) statePath() string {
	return filepath.Join(m.Dir, "cores.json")
}

// Resolve returns the path Obelisk will actually launch for a core: the managed
// copy when one exists, otherwise a system installation.
func (m *Manager) Resolve(k Kind) (string, bool, error) {
	managed := m.binaryPath(k)
	if st, err := os.Stat(managed); err == nil && !st.IsDir() {
		return managed, true, nil
	}

	for _, dir := range m.ExtraLookupPaths {
		candidate := filepath.Join(dir, k.BinaryName())
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, false, nil
		}
	}
	if path, err := exec.LookPath(k.BinaryName()); err == nil {
		return path, false, nil
	}
	return "", false, fmt.Errorf("%s is not installed", k)
}

// Detect inspects the installed core, asking the binary itself what version it
// is rather than trusting the state file. The binary is the authority: it may
// have been replaced by opkg, by a rollback, or by hand.
func (m *Manager) Detect(ctx context.Context, k Kind) (*Installed, error) {
	path, managed, err := m.Resolve(k)
	if err != nil {
		return nil, err
	}

	version, err := probeVersion(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("%s at %s: %w", k, path, err)
	}

	out := &Installed{
		Kind:    k,
		Path:    path,
		Version: version,
		Managed: managed,
	}
	if st, err := os.Stat(path); err == nil {
		out.Size = st.Size()
	}

	// The state file supplies what the binary cannot report about itself: where
	// it came from and whether its checksum was ever verified.
	if managed {
		if recorded, err := m.loadState(); err == nil {
			if prev, ok := recorded[k]; ok && prev.Version == version {
				out.SHA256 = prev.SHA256
				out.InstalledAt = prev.InstalledAt
				out.AssetURL = prev.AssetURL
				out.Verified = prev.Verified
			}
		}
	}
	return out, nil
}

// Status reports the installed and available versions of one core.
func (m *Manager) Status(ctx context.Context, k Kind, target Target) Status {
	st := Status{Kind: k}

	if installed, err := m.Detect(ctx, k); err == nil {
		st.Installed = installed
	} else if !errors.Is(err, exec.ErrNotFound) {
		st.Error = err.Error()
	}

	available, err := m.source().Latest(ctx, k, target)
	if err != nil {
		// A failed lookup must not hide a working installation.
		if st.Error == "" {
			st.Error = err.Error()
		}
		return st
	}
	st.Available = available

	if st.Installed != nil {
		st.UpdateAvailable = normalizeVersion(available.Version) != normalizeVersion(st.Installed.Version)
	}
	return st
}

// Install downloads a release and puts it in place atomically.
//
// The previous binary is kept as a backup so that a core which turns out to be
// broken on this hardware can be reverted without a network round trip — which
// matters, because the thing that just broke is the router's only way out.
//
// The caller is responsible for stopping the core first. Replacing a running
// executable through rename is safe on Linux, but the running process keeps the
// old version until it is restarted, so a swap without a restart quietly does
// nothing.
func (m *Manager) Install(ctx context.Context, rel *Release) (*Installed, error) {
	if rel == nil || rel.AssetURL == "" {
		return nil, fmt.Errorf("install: release has no asset")
	}
	if err := os.MkdirAll(m.Dir, 0o755); err != nil {
		return nil, fmt.Errorf("install: %w", err)
	}

	archive, digest, err := m.download(ctx, rel)
	if err != nil {
		return nil, err
	}
	defer os.Remove(archive)

	verified := false
	if rel.ChecksumURL != "" {
		expected, err := m.fetchChecksum(ctx, rel.ChecksumURL)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel.Kind, err)
		}
		if expected != digest {
			return nil, fmt.Errorf("%s %s: checksum mismatch (expected %s, got %s)",
				rel.Kind, rel.Version, expected, digest)
		}
		verified = true
	}

	staged := m.binaryPath(rel.Kind) + ".new"
	defer os.Remove(staged)
	if err := extractBinary(archive, rel.AssetName, rel.Kind.BinaryName(), staged); err != nil {
		return nil, fmt.Errorf("%s %s: %w", rel.Kind, rel.Version, err)
	}

	// Ask the freshly extracted binary what it is before trusting it with the
	// router's traffic. This catches a wrong-architecture asset immediately,
	// where the alternative is a core that fails to exec at the worst moment.
	//
	// A core being staged for a different machine cannot be run here, so that
	// check is skipped rather than faked — the version then comes from the
	// release tag, which is all that is knowable without executing the file.
	version := normalizeVersion(rel.Version)
	if rel.Target.Equal(CurrentTarget()) {
		reported, err := probeVersion(ctx, staged)
		if err != nil {
			return nil, fmt.Errorf("%s %s: downloaded binary does not run here: %w", rel.Kind, rel.Version, err)
		}
		if normalizeVersion(reported) != version {
			return nil, fmt.Errorf("%s: downloaded %s but the binary reports %s", rel.Kind, rel.Version, reported)
		}
		version = reported
	}

	if err := m.swapIn(rel.Kind, staged); err != nil {
		return nil, err
	}

	size := int64(0)
	if st, err := os.Stat(m.binaryPath(rel.Kind)); err == nil {
		size = st.Size()
	}
	installed := &Installed{
		Kind:        rel.Kind,
		Target:      rel.Target.String(),
		Path:        m.binaryPath(rel.Kind),
		Version:     version,
		SHA256:      digest,
		Size:        size,
		InstalledAt: time.Now().UTC(),
		AssetURL:    rel.AssetURL,
		Verified:    verified,
		Managed:     true,
	}
	if err := m.recordState(installed); err != nil {
		return installed, fmt.Errorf("%s installed but state not recorded: %w", rel.Kind, err)
	}
	return installed, nil
}

// Update installs the latest release when it differs from what is installed.
func (m *Manager) Update(ctx context.Context, k Kind, target Target) (*UpdateResult, error) {
	result := &UpdateResult{Kind: k}

	if current, err := m.Detect(ctx, k); err == nil {
		result.Previous = current
		// An update never overwrites a binary Obelisk did not install: the new
		// copy goes to the managed directory, which Resolve searches first. The
		// system copy stays untouched and reachable, so a package manager that
		// owns it is not fighting anyone — but the user is told that their
		// "obelisk core update" now shadows it, because otherwise an opkg
		// upgrade later would silently appear to do nothing.
		if !current.Managed {
			result.Shadows = current.Path
		}
	}

	latest, err := m.source().Latest(ctx, k, target)
	if err != nil {
		return nil, err
	}
	if result.Previous != nil && normalizeVersion(result.Previous.Version) == normalizeVersion(latest.Version) {
		result.AlreadyNew = true
		result.Current = result.Previous
		return result, nil
	}

	installed, err := m.Install(ctx, latest)
	if err != nil {
		return nil, err
	}
	result.Current = installed
	result.Changed = true
	return result, nil
}

// Rollback restores the backup taken by the last install.
func (m *Manager) Rollback(ctx context.Context, k Kind) (*Installed, error) {
	backup := m.backupPath(k)
	if _, err := os.Stat(backup); err != nil {
		return nil, fmt.Errorf("%s: no backup to roll back to", k)
	}

	current := m.binaryPath(k)
	// The current binary becomes the backup, so a rollback can be undone.
	swap := current + ".rollback"
	_ = os.Remove(swap)
	if err := os.Rename(current, swap); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("%s: %w", k, err)
	}
	if err := os.Rename(backup, current); err != nil {
		_ = os.Rename(swap, current)
		return nil, fmt.Errorf("%s: %w", k, err)
	}
	_ = os.Rename(swap, backup)

	installed, err := m.Detect(ctx, k)
	if err != nil {
		return nil, err
	}
	installed.Verified = false
	if err := m.recordState(installed); err != nil {
		return installed, err
	}
	return installed, nil
}

// download streams a release asset to a temporary file, hashing as it goes so
// the payload is never read twice.
func (m *Manager) download(ctx context.Context, rel *Release) (path string, sha256hex string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rel.AssetURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "Obelisk")

	resp, err := m.client().Do(req)
	if err != nil {
		return "", "", fmt.Errorf("%s: download: %w", rel.Kind, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("%s: download returned HTTP %s", rel.Kind, resp.Status)
	}

	// The temporary file shares a directory with the destination so the later
	// rename stays within one filesystem and therefore stays atomic.
	tmp, err := os.CreateTemp(m.Dir, "."+string(rel.Kind)+"-*.download")
	if err != nil {
		return "", "", err
	}
	defer tmp.Close()

	hasher := sha256.New()
	limit := int64(maxBinarySize)
	if rel.Size > 0 {
		limit = rel.Size
	}
	written, err := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(resp.Body, limit+1))
	if err != nil {
		os.Remove(tmp.Name())
		return "", "", fmt.Errorf("%s: download: %w", rel.Kind, err)
	}
	if written > limit {
		os.Remove(tmp.Name())
		return "", "", fmt.Errorf("%s: download is larger than the announced %d bytes", rel.Kind, limit)
	}

	return tmp.Name(), hex.EncodeToString(hasher.Sum(nil)), nil
}

// fetchChecksum downloads and parses a publisher checksum file.
func (m *Manager) fetchChecksum(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Obelisk")

	resp, err := m.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("checksum download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("checksum download returned HTTP %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", fmt.Errorf("checksum download: %w", err)
	}
	return parseSHA256(body)
}

// swapIn moves a staged binary into place, keeping the previous one as a backup.
func (m *Manager) swapIn(k Kind, staged string) error {
	current := m.binaryPath(k)
	backup := m.backupPath(k)

	if _, err := os.Stat(current); err == nil {
		_ = os.Remove(backup)
		if err := os.Rename(current, backup); err != nil {
			return fmt.Errorf("%s: cannot set aside the current binary: %w", k, err)
		}
	}

	if err := os.Rename(staged, current); err != nil {
		// Put the old binary back rather than leaving the router with none.
		_ = os.Rename(backup, current)
		return fmt.Errorf("%s: cannot install the new binary: %w", k, err)
	}
	return nil
}

// loadState reads the record of what Obelisk installed.
func (m *Manager) loadState() (map[Kind]*Installed, error) {
	data, err := os.ReadFile(m.statePath())
	if err != nil {
		return map[Kind]*Installed{}, err
	}
	var state map[Kind]*Installed
	if err := json.Unmarshal(data, &state); err != nil {
		return map[Kind]*Installed{}, err
	}
	if state == nil {
		state = map[Kind]*Installed{}
	}
	return state, nil
}

// recordState persists one core's installation record.
func (m *Manager) recordState(installed *Installed) error {
	state, _ := m.loadState()
	state[installed.Kind] = installed

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	// Written through a temporary file so an interrupted write cannot leave
	// Obelisk unable to parse its own state on the next boot.
	tmp := m.statePath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, m.statePath())
}

// versionPattern matches the first dotted version in a core's version output.
var versionPattern = regexp.MustCompile(`\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?`)

// probeVersion runs a core binary and reads the version out of its output.
//
// Both cores answer "version" on stdout, but with different wording — Xray
// starts with "Xray 26.3.27 (...)" while sing-box says "sing-box version
// 1.13.16" — so the version is matched by shape rather than by position.
func probeVersion(ctx context.Context, binary string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, binary, "version").CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return "", fmt.Errorf("%w: %s", err, firstLine(trimmed))
		}
		return "", err
	}

	match := versionPattern.FindString(string(out))
	if match == "" {
		return "", fmt.Errorf("version output not recognized: %q", firstLine(strings.TrimSpace(string(out))))
	}
	return match, nil
}

// normalizeVersion strips the leading "v" so that a release tag and the version
// a binary reports about itself can be compared.
func normalizeVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
