// Package api exposes Obelisk over HTTP: a JSON API for the web interface and
// for scripts, plus the interface's own static files.
//
// Everything it does goes through internal/app, so the browser and the command
// line drive exactly the same state rather than two copies of it.
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/obelisk-project/obelisk/internal/app"
	"github.com/obelisk-project/obelisk/internal/config"
	"github.com/obelisk-project/obelisk/internal/cores"
	"github.com/obelisk-project/obelisk/internal/routing"
	"github.com/obelisk-project/obelisk/internal/subs"
)

// Options configures the HTTP server.
type Options struct {
	// Listen is the address to bind, for example "0.0.0.0:24080".
	Listen string

	// Token authenticates requests. When empty one is generated and returned by
	// New, so that the interface is never accidentally left open: a VPN client's
	// control plane can change where a whole household's traffic goes.
	Token string

	// Static serves the web interface. Nil disables it and leaves only the API.
	Static fs.FS
}

// Server is the HTTP front end.
type Server struct {
	app   *app.App
	opts  Options
	token string
	mux   *http.ServeMux
	http  *http.Server
}

// New builds the server. The returned token is the one clients must present.
func New(a *app.App, opts Options) (*Server, string, error) {
	token := opts.Token
	if token == "" {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return nil, "", fmt.Errorf("api: cannot generate a token: %w", err)
		}
		token = hex.EncodeToString(buf)
	}

	s := &Server{
		app:   a,
		opts:  opts,
		token: token,
		mux:   http.NewServeMux(),
	}
	s.routes()

	s.http = &http.Server{
		Addr:    opts.Listen,
		Handler: s.mux,
		// The events endpoint is a long-lived stream, so a write deadline would
		// cut it; read and idle timeouts still bound the damage a stuck client
		// can do.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return s, token, nil
}

// ListenAndServe runs the server until the context is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	errs := make(chan error, 1)
	go func() {
		if err := s.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
		close(errs)
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return s.http.Shutdown(shutdown)
	}
}

// routes registers every endpoint.
func (s *Server) routes() {
	api := func(pattern string, h http.HandlerFunc) {
		s.mux.Handle(pattern, s.authenticated(h))
	}

	s.mux.HandleFunc("POST /api/login", s.handleLogin)

	api("GET /api/status", s.handleStatus)
	api("GET /api/nodes", s.handleNodes)
	api("POST /api/nodes/test", s.handleNodeTest)
	api("POST /api/nodes/select", s.handleNodeSelect)
	api("GET /api/traffic", s.handleTraffic)
	api("GET /api/history", s.handleHistory)
	api("GET /api/nodes/stats", s.handleNodeStats)

	api("GET /api/subscriptions", s.handleSubscriptionList)
	api("POST /api/subscriptions", s.handleSubscriptionAdd)
	api("DELETE /api/subscriptions/{id}", s.handleSubscriptionDelete)
	api("POST /api/subscriptions/{id}/enabled", s.handleSubscriptionToggle)
	api("POST /api/subscriptions/{id}/import-rules", s.handleSubscriptionImportRules)
	api("POST /api/refresh", s.handleRefresh)
	api("POST /api/subscriptions/{id}/refresh", s.handleSubscriptionRefresh)
	api("POST /api/subscriptions/{id}/user-agent", s.handleSubscriptionUserAgent)
	api("GET /api/user-agents", s.handleUserAgents)
	api("GET /api/config/singbox", s.handleConfigPreview)

	api("GET /api/rules", s.handleRuleList)
	api("POST /api/rules", s.handleRuleAdd)
	api("DELETE /api/rules/{id}", s.handleRuleDelete)
	api("POST /api/rules/{id}/enabled", s.handleRuleToggle)
	api("POST /api/rules/{id}/move", s.handleRuleMove)
	api("POST /api/rules/test", s.handleRuleTest)

	api("GET /api/settings", s.handleSettingsGet)
	api("PUT /api/settings", s.handleSettingsPut)

	api("GET /api/host", s.handleHost)
	api("GET /api/connections", s.handleConnections)
	api("GET /api/health", s.handleHealth)
	api("GET /api/firewall", s.handleFirewall)
	api("GET /api/cores", s.handleCores)
	api("POST /api/cores/{kind}/update", s.handleCoreUpdate)

	api("POST /api/connect", s.handleConnect)
	api("POST /api/disconnect", s.handleDisconnect)

	api("GET /api/logs", s.handleLogs)
	api("GET /api/events", s.handleEvents)

	if s.opts.Static != nil {
		s.mux.Handle("/", s.static())
	}
}

// authenticated rejects requests without the token.
func (s *Server) authenticated(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			writeError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next(w, r)
	})
}

// authorized accepts the token from a bearer header, a cookie, or — for the
// events stream, which the browser's EventSource cannot add headers to — a
// query parameter.
func (s *Server) authorized(r *http.Request) bool {
	if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
		if s.tokenMatches(strings.TrimPrefix(header, "Bearer ")) {
			return true
		}
	}
	if c, err := r.Cookie("obelisk_token"); err == nil && s.tokenMatches(c.Value) {
		return true
	}
	if q := r.URL.Query().Get("token"); q != "" && s.tokenMatches(q) {
		return true
	}
	return false
}

// tokenMatches compares in constant time, so that a wrong token cannot be
// discovered one character at a time by measuring how long the check took.
func (s *Server) tokenMatches(candidate string) bool {
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(s.token)) == 1
}

// handleLogin exchanges the token for a cookie.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.tokenMatches(body.Token) {
		writeError(w, http.StatusUnauthorized, "wrong token")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "obelisk_token",
		Value:    body.Token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   30 * 24 * 3600,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// static serves the embedded interface, falling back to the entry point so that
// a deep link reloads into the application instead of a 404.
func (s *Server) static() http.Handler {
	files := http.FileServer(http.FS(s.opts.Static))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		clean := strings.TrimPrefix(r.URL.Path, "/")
		if clean == "" {
			clean = "index.html"
		}
		if _, err := fs.Stat(s.opts.Static, clean); err != nil {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		files.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------- handlers

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.app.Status())
}

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.app.Nodes())
}

// handleNodeTest measures latency through the running cores.
func (s *Server) handleNodeTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tags []string `json:"tags"`
	}
	// An empty body means "test everything", so a decode failure on no content
	// is not an error.
	_ = decode(r, &body)

	results, err := s.app.TestNodes(r.Context(), body.Tags)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, results)
}

// handleNodeSelect points the proxy group at one node.
func (s *Server) handleNodeSelect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tag string `json:"tag"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Tag == "" {
		writeError(w, http.StatusBadRequest, "no node given")
		return
	}
	if err := s.app.SelectNode(r.Context(), body.Tag); err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "active": s.app.ActiveNode(r.Context())})
}

// handleTraffic reports throughput and the last two minutes, from memory.
func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.app.Traffic())
}

// handleHistory reports traffic over a longer period, from the database.
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "day"
	}
	history, err := s.app.History(r.Context(), period)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, history)
}

// handleNodeStats summarizes how each node has behaved over the last day.
func (s *Server) handleNodeStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.app.NodeStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleSubscriptionList(w http.ResponseWriter, r *http.Request) {
	cfg := s.app.Config()
	subscriptions := cfg.Subscriptions
	if subscriptions == nil {
		subscriptions = []config.Subscription{}
	}
	writeJSON(w, http.StatusOK, subscriptions)
}

func (s *Server) handleSubscriptionAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name      string `json:"name"`
		URL       string `json:"url"`
		UserAgent string `json:"user_agent"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	sub, err := s.app.AddSubscription(r.Context(), body.Name, body.URL, body.UserAgent)
	if err != nil {
		// The subscription may have been stored even though the first fetch
		// failed; report both so the interface can show the error next to it.
		status := http.StatusBadGateway
		if sub == nil {
			status = http.StatusBadRequest
		}
		writeJSON(w, status, map[string]any{"error": err.Error(), "subscription": sub})
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

func (s *Server) handleSubscriptionDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.app.DeleteSubscription(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSubscriptionToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SetSubscriptionEnabled(r.Context(), r.PathValue("id"), body.Enabled); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSubscriptionImportRules turns the provider's own routing on or off.
func (s *Server) handleSubscriptionImportRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SetSubscriptionImportRules(r.Context(), r.PathValue("id"), body.Enabled); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Refresh(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.app.Status())
}

// handleSubscriptionRefresh re-fetches one subscription.
func (s *Server) handleSubscriptionRefresh(w http.ResponseWriter, r *http.Request) {
	if err := s.app.RefreshOne(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleSubscriptionUserAgent changes the identity a subscription is fetched
// with, which is what decides the format a panel serves.
func (s *Server) handleSubscriptionUserAgent(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserAgent string `json:"user_agent"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SetSubscriptionUserAgent(r.Context(), r.PathValue("id"), body.UserAgent); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleUserAgents lists the identities panels are known to recognise.
func (s *Server) handleUserAgents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, subs.UserAgentPresets)
}

// handleConfigPreview returns the configuration the cores would be given.
func (s *Server) handleConfigPreview(w http.ResponseWriter, r *http.Request) {
	raw, err := s.app.PreviewConfig()
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) handleRuleList(w http.ResponseWriter, r *http.Request) {
	rules, conflicts := s.app.Rules()
	if rules == nil {
		rules = []routing.Entry{}
	}
	if conflicts == nil {
		conflicts = []routing.Conflict{}
	}
	provider := s.app.ProviderRules()
	if provider == nil {
		provider = []routing.Entry{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rules":     rules,
		"provider":  provider,
		"conflicts": conflicts,
		"summary":   routing.Summarize(rules),
	})
}

func (s *Server) handleRuleAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Entries []string `json:"entries"`
		Text    string   `json:"text"`
		Action  string   `json:"action"`
		Target  string   `json:"target"`
		Sources []string `json:"sources"`
		Comment string   `json:"comment"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// The interface offers one box; whether the user typed one entry or pasted
	// fifty lines into it is not something they should have to declare.
	entries := body.Entries
	if body.Text != "" {
		for _, line := range strings.Split(body.Text, "\n") {
			if trimmed := strings.TrimSpace(line); trimmed != "" &&
				!strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, "//") {
				entries = append(entries, trimmed)
			}
		}
	}
	if len(entries) == 0 {
		writeError(w, http.StatusBadRequest, "nothing to add")
		return
	}

	action, err := routing.ParseAction(body.Action)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	added, lineErrors, err := s.app.AddRules(entries, action, body.Target, body.Sources, body.Comment)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if added == nil {
		added = []routing.Entry{}
	}
	if lineErrors == nil {
		lineErrors = []routing.LineError{}
	}

	_, conflicts := s.app.Rules()
	if conflicts == nil {
		conflicts = []routing.Conflict{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"added":     added,
		"rejected":  lineErrors,
		"conflicts": conflicts,
	})
}

func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	n, err := s.app.DeleteRule(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n == 0 {
		writeError(w, http.StatusNotFound, "no such rule")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": n})
}

func (s *Server) handleRuleToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.SetRuleEnabled(r.PathValue("id"), body.Enabled); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRuleMove(w http.ResponseWriter, r *http.Request) {
	var body struct {
		To int `json:"to"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.MoveRule(r.PathValue("id"), body.To); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRuleTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Destination string `json:"destination"`
		From        string `json:"from"`
	}
	if err := decode(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	decision, effective, err := s.app.TestRoute(body.Destination, body.From)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision":  decision,
		"effective": effective,
	})
}

func (s *Server) handleSettingsGet(w http.ResponseWriter, r *http.Request) {
	cfg := s.app.Config()
	writeJSON(w, http.StatusOK, cfg.Settings)
}

func (s *Server) handleSettingsPut(w http.ResponseWriter, r *http.Request) {
	var settings config.Settings
	if err := decode(r, &settings); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.app.UpdateSettings(settings); err != nil {
		// A rejected setting is the caller's mistake, not the daemon's failure,
		// and the interface tells the two apart by the status.
		status := http.StatusInternalServerError
		if !settings.Split.Valid() {
			status = http.StatusBadRequest
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, settings)
}

// handleHost reports what Obelisk is running on.
func (s *Server) handleHost(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.app.Host())
}

// handleConnections summarizes the live connection table by LAN device and by
// destination.
func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	live, err := s.app.LiveConnections(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, live)
}

// handleHealth answers the two questions separately: is there internet, and is
// the tunnel actually carrying anything.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.app.Health(r.Context()))
}

// handleFirewall reports the capture rules, including the exact script that
// would be installed, so it can be reviewed without root access.
func (s *Server) handleFirewall(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.app.FirewallStatus(r.Context()))
}

func (s *Server) handleCores(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.app.CoreStatus(r.Context()))
}

func (s *Server) handleCoreUpdate(w http.ResponseWriter, r *http.Request) {
	kind, err := cores.ParseKind(r.PathValue("kind"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := s.app.UpdateCore(r.Context(), kind)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Connect(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.app.Status())
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.app.Disconnect(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.app.Status())
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, s.app.Logs(r.URL.Query().Get("core"), limit))
}

// handleEvents streams state changes as Server-Sent Events.
//
// SSE rather than WebSockets: the traffic here is one-way and low volume, and
// SSE needs no library, no upgrade handshake and no ping loop — it is an HTTP
// response that never ends. The browser reconnects on its own if it drops.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	events, cancel := s.app.Events()
	defer cancel()

	// A comment line every 25 seconds keeps proxies and NAT tables from
	// deciding an idle connection is dead.
	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case e, ok := <-events:
			if !ok {
				return
			}
			payload, err := json.Marshal(e)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, payload)
			flusher.Flush()
		}
	}
}

// ---------------------------------------------------------------- helpers

func decode(r *http.Request, v any) error {
	if r.Body == nil {
		return fmt.Errorf("a request body is required")
	}
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("malformed request: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("api: writing response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
