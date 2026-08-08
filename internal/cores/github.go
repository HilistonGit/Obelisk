package cores

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Release is one installable version of a core, already resolved down to the
// single asset that matches the requested target.
type Release struct {
	Kind        Kind      `json:"kind"`
	Target      Target    `json:"target"`
	Version     string    `json:"version"`
	AssetName   string    `json:"asset_name"`
	AssetURL    string    `json:"asset_url"`
	ChecksumURL string    `json:"checksum_url,omitempty"`
	Size        int64     `json:"size"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
	PageURL     string    `json:"page_url,omitempty"`
}

// Source looks up releases on GitHub.
type Source struct {
	Client *http.Client

	// Token is an optional GitHub token. Anonymous requests are limited to 60
	// per hour per address, which a single router will never approach but a
	// shared NAT can; supplying a token raises the limit.
	Token string

	// BaseURL overrides the API root, for tests.
	BaseURL string

	Timeout time.Duration
}

func (s *Source) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{Timeout: timeout}
}

func (s *Source) baseURL() string {
	if s.BaseURL != "" {
		return strings.TrimSuffix(s.BaseURL, "/")
	}
	return "https://api.github.com"
}

// githubRelease mirrors the subset of GitHub's release object Obelisk reads.
type githubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	HTMLURL     string    `json:"html_url"`
	Prerelease  bool      `json:"prerelease"`
	Draft       bool      `json:"draft"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

// Latest returns the newest stable release of a core for the given target.
func (s *Source) Latest(ctx context.Context, kind Kind, target Target) (*Release, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", s.baseURL(), kind.Repo())
	return s.fetchRelease(ctx, kind, target, url)
}

// ByTag returns a specific release, so that a user who needs to stay on — or go
// back to — a known-good version can say so.
func (s *Source) ByTag(ctx context.Context, kind Kind, target Target, tag string) (*Release, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/tags/%s", s.baseURL(), kind.Repo(), tag)
	return s.fetchRelease(ctx, kind, target, url)
}

func (s *Source) fetchRelease(ctx context.Context, kind Kind, target Target, url string) (*Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Obelisk")
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}

	resp, err := s.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: release lookup: %w", kind, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%s: no such release", kind)
	case resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") == "0":
		reset := resp.Header.Get("X-RateLimit-Reset")
		return nil, fmt.Errorf("%s: GitHub rate limit exhausted (resets at %s); set a token to raise it", kind, reset)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, fmt.Errorf("%s: release lookup returned HTTP %s", kind, resp.Status)
	}

	var rel githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("%s: malformed release response: %w", kind, err)
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("%s: release carries no tag", kind)
	}

	// sing-box embeds the version in its asset names, so the asset can only be
	// named once the tag is known.
	wantAsset, err := AssetName(kind, target, rel.TagName)
	if err != nil {
		return nil, err
	}
	wantChecksum := ChecksumAssetName(kind, wantAsset)

	out := &Release{
		Kind:        kind,
		Target:      target,
		Version:     rel.TagName,
		AssetName:   wantAsset,
		PublishedAt: rel.PublishedAt,
		Prerelease:  rel.Prerelease,
		PageURL:     rel.HTMLURL,
	}
	for _, a := range rel.Assets {
		switch a.Name {
		case wantAsset:
			out.AssetURL = a.URL
			out.Size = a.Size
		case wantChecksum:
			out.ChecksumURL = a.URL
		}
	}

	if out.AssetURL == "" {
		return nil, fmt.Errorf("%s %s publishes no asset named %q for %s",
			kind, rel.TagName, wantAsset, target)
	}
	return out, nil
}
