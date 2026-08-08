package subs

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/obelisk-project/obelisk/internal/model"
)

// parseVLESS handles the standard VLESS share link:
//
//	vless://<uuid>@<host>:<port>?<stream params>#<tag>
func parseVLESS(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)

	u, err := url.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("vless: missing uuid")
	}

	host, port, err := parseHostPort(u.Host, 0)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}

	n := &model.Node{
		Name:     name,
		Protocol: model.ProtoVLESS,
		Server:   host,
		Port:     port,
		UUID:     u.User.Username(),
	}
	applyStreamParams(n, u.Query())
	return n, nil
}

// parseTrojan handles the Trojan share link. Trojan is TLS by definition, so a
// link that omits the security parameter still means TLS.
func parseTrojan(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)

	u, err := url.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	if u.User == nil {
		return nil, fmt.Errorf("trojan: missing password")
	}

	// Most panels emit the password as the whole userinfo. A few emit
	// "ignored:password"; take the password half when the username half is empty.
	password := u.User.Username()
	if pw, ok := u.User.Password(); ok && password == "" {
		password = pw
	}
	if password == "" {
		return nil, fmt.Errorf("trojan: missing password")
	}

	host, port, err := parseHostPort(u.Host, 443)
	if err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}

	n := &model.Node{
		Name:     name,
		Protocol: model.ProtoTrojan,
		Server:   host,
		Port:     port,
		Password: password,
	}
	applyStreamParams(n, u.Query())
	if n.TLS.Security == model.SecurityNone {
		n.TLS.Security = model.SecurityTLS
		if n.TLS.SNI == "" {
			n.TLS.SNI = host
		}
	}
	return n, nil
}

// parseVMess handles both VMess link dialects: the v2rayN base64-JSON blob that
// dominates in practice, and the newer URI form that mirrors VLESS.
func parseVMess(raw string) (*model.Node, error) {
	payload := strings.TrimPrefix(raw, "vmess://")

	// The URI form is recognizable by its userinfo separator; the base64 form
	// cannot contain a bare "@" before the query.
	if decoded, err := decodeBase64(payload); err == nil {
		trimmed := strings.TrimSpace(string(decoded))
		if strings.HasPrefix(trimmed, "{") {
			return parseVMessJSON(trimmed)
		}
	}
	return parseVMessURI(raw)
}

// vmessLegacy mirrors the v2rayN JSON blob. Panels disagree about whether the
// numeric fields are numbers or strings, so everything is decoded through
// json.RawMessage and coerced.
func parseVMessJSON(payload string) (*model.Node, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &doc); err != nil {
		return nil, fmt.Errorf("vmess: malformed JSON payload: %w", err)
	}

	host, port, err := parseHostPort(
		joinHostPort(jsonString(doc, "add"), jsonString(doc, "port")), 0)
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}

	n := &model.Node{
		Name:          jsonString(doc, "ps"),
		Protocol:      model.ProtoVMess,
		Server:        host,
		Port:          port,
		UUID:          jsonString(doc, "id"),
		AlterID:       atoiOr(jsonString(doc, "aid"), 0),
		VMessSecurity: firstNonEmpty(jsonString(doc, "scy"), "auto"),
	}

	// The JSON blob uses its own key names, so it is translated into the same
	// query-parameter vocabulary that applyStreamParams already understands.
	q := url.Values{}
	q.Set("type", jsonString(doc, "net"))
	q.Set("headerType", jsonString(doc, "type"))
	q.Set("host", jsonString(doc, "host"))
	q.Set("path", jsonString(doc, "path"))
	q.Set("security", jsonString(doc, "tls"))
	q.Set("sni", jsonString(doc, "sni"))
	q.Set("alpn", jsonString(doc, "alpn"))
	q.Set("fp", jsonString(doc, "fp"))
	q.Set("mode", jsonString(doc, "mode"))
	if v := jsonString(doc, "allowInsecure"); v != "" {
		q.Set("allowInsecure", v)
	}
	applyStreamParams(n, q)

	// In the v2rayN dialect the "path" key doubles as the gRPC service name and
	// as the mKCP seed, which applyStreamParams cannot know from the query alone.
	switch n.Transport.Type {
	case model.TransportGRPC:
		if n.Transport.ServiceName == "" {
			n.Transport.ServiceName = strings.TrimPrefix(jsonString(doc, "path"), "/")
			n.Transport.Path = ""
		}
	case model.TransportKCP:
		if n.Transport.Seed == "" {
			n.Transport.Seed = jsonString(doc, "path")
			n.Transport.Path = ""
		}
	}
	return n, nil
}

// parseVMessURI handles vmess://<uuid>@<host>:<port>?<stream params>#<tag>.
func parseVMessURI(raw string) (*model.Node, error) {
	body, name := splitFragment(raw)

	u, err := url.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("vmess: missing uuid")
	}

	host, port, err := parseHostPort(u.Host, 0)
	if err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}

	q := u.Query()
	n := &model.Node{
		Name:          name,
		Protocol:      model.ProtoVMess,
		Server:        host,
		Port:          port,
		UUID:          u.User.Username(),
		AlterID:       atoiOr(q.Get("aid"), 0),
		VMessSecurity: firstNonEmpty(q.Get("scy"), q.Get("encryption"), "auto"),
	}
	applyStreamParams(n, q)
	// "encryption" means the VMess cipher here, not the VLESS extension.
	n.TLS.Encryption = ""
	return n, nil
}

// jsonString coerces a v2rayN field to a string regardless of whether the panel
// emitted it as a JSON string or a JSON number.
func jsonString(doc map[string]json.RawMessage, key string) string {
	raw, ok := doc[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err == nil {
		return strings.TrimSuffix(fmt.Sprintf("%.0f", f), ".0")
	}
	return strings.Trim(strings.TrimSpace(string(raw)), `"`)
}

// joinHostPort builds an authority string, bracketing bare IPv6 literals so that
// net.SplitHostPort can take it apart again.
func joinHostPort(host, port string) string {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}
