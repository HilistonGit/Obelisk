package subs

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// UserAgentPresets are the identities panels are known to recognise.
//
// Panels serve different formats to different clients, keyed on the User-Agent:
// the same URL that returns a bare list of links to one name returns a full
// configuration with the provider's own routing to another. Which names a given
// panel knows is not discoverable, so the useful ones are offered as presets and
// the field stays editable.
var UserAgentPresets = []struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Note  string `json:"note"`
}{
	{"Obelisk (default)", DefaultUserAgent, "names the cores Obelisk drives, which most panels match on"},
	{"Happ", "Happ/1.0", "many panels serve a full Xray configuration to this"},
	{"v2rayNG", "v2rayNG/1.9.0", "another name panels commonly recognise"},
	{"sing-box", "sing-box/1.13.0", "asks for a sing-box configuration where one is offered"},
	{"Clash Meta", "clash-verge/1.6.0", "asks for a Clash configuration"},
}

// DefaultUserAgent is what Obelisk identifies itself as when fetching a
// subscription.
//
// The user agent is not cosmetic here. Many panels inspect it and serve a
// completely different payload format to each client they recognize, so being
// able to override it per subscription is the difference between receiving a
// node list and receiving an HTML error page.
const DefaultUserAgent = "Obelisk/0.1 (OpenWrt) sing-box/1.13 Xray/26.3"

// FetchOptions configures a subscription fetch.
type FetchOptions struct {
	UserAgent string
	HWID      string
	Timeout   time.Duration

	// MaxBytes caps the response size. A subscription is a few kilobytes; a
	// multi-megabyte response is a misconfigured URL or a hostile one, and
	// either way it must not be read into a router's memory.
	MaxBytes int64

	// ETag and LastModified, when carried over from a previous fetch, let the
	// server answer 304 and save the parse entirely.
	ETag         string
	LastModified string

	Client *http.Client
}

func (o *FetchOptions) applyDefaults() {
	if o.UserAgent == "" {
		o.UserAgent = DefaultUserAgent
	}
	if o.Timeout == 0 {
		o.Timeout = 30 * time.Second
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = 8 << 20
	}
}

// FetchResult is everything one subscription fetch produced.
type FetchResult struct {
	Result *Result `json:"result"`

	// NotModified reports that the server answered 304 and Result is nil.
	NotModified bool `json:"not_modified"`

	// UserInfo carries the quota and expiry the panel reported, if any.
	UserInfo *UserInfo `json:"user_info,omitempty"`

	// ProfileTitle is the display name the panel suggests for the subscription.
	ProfileTitle string `json:"profile_title,omitempty"`

	// UpdateInterval is how often the panel asks to be polled.
	UpdateInterval time.Duration `json:"update_interval,omitempty"`

	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
}

// Fetch downloads a subscription and parses it.
func Fetch(ctx context.Context, url string, opts FetchOptions) (*FetchResult, error) {
	opts.applyDefaults()

	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: opts.Timeout}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("subscription request: %w", err)
	}
	req.Header.Set("User-Agent", opts.UserAgent)
	req.Header.Set("Accept", "*/*")
	if opts.HWID != "" {
		req.Header.Set("X-Hwid", opts.HWID)
		req.Header.Set("X-Device-Os", runtime.GOOS)
		req.Header.Set("X-Device-Model", "Obelisk "+runtime.GOARCH)
	}
	if opts.ETag != "" {
		req.Header.Set("If-None-Match", opts.ETag)
	}
	if opts.LastModified != "" {
		req.Header.Set("If-Modified-Since", opts.LastModified)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("subscription fetch: %w", err)
	}
	defer resp.Body.Close()

	out := &FetchResult{
		FetchedAt:      time.Now(),
		ETag:           resp.Header.Get("ETag"),
		LastModified:   resp.Header.Get("Last-Modified"),
		UserInfo:       ParseUserInfo(resp.Header.Get("subscription-userinfo")),
		ProfileTitle:   decodeProfileTitle(resp.Header.Get("profile-title")),
		UpdateInterval: parseUpdateInterval(resp.Header.Get("profile-update-interval")),
	}

	if resp.StatusCode == http.StatusNotModified {
		out.NotModified = true
		return out, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("subscription returned HTTP %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("subscription body: %w", err)
	}
	if int64(len(body)) > opts.MaxBytes {
		return nil, fmt.Errorf("subscription body exceeds %d bytes", opts.MaxBytes)
	}

	result, err := Parse(body)
	if err != nil {
		return nil, err
	}
	if len(result.Nodes) == 0 {
		return nil, fmt.Errorf("subscription contains no usable servers (%d skipped)", len(result.Skipped))
	}
	out.Result = result
	return out, nil
}

// decodeProfileTitle reads the profile-title header, which panels send either as
// plain text or with a "base64:" prefix so that non-ASCII names survive a header.
func decodeProfileTitle(header string) string {
	header = strings.TrimSpace(header)
	if header == "" {
		return ""
	}
	if encoded, ok := strings.CutPrefix(header, "base64:"); ok {
		if decoded, err := decodeBase64(encoded); err == nil {
			return strings.TrimSpace(string(decoded))
		}
	}
	return header
}

// parseUpdateInterval reads the profile-update-interval header, which is a
// number of hours.
func parseUpdateInterval(header string) time.Duration {
	hours, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || hours <= 0 {
		return 0
	}
	return time.Duration(hours) * time.Hour
}
