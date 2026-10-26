package subs

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/obelisk-project/obelisk/internal/core/singbox"
	"github.com/obelisk-project/obelisk/internal/model"
	"github.com/obelisk-project/obelisk/internal/routing"
)

// ParseXray reads a full Xray-core configuration document.
//
// Panels commonly serve this format, and it is the richest thing they publish:
// alongside the servers it carries a complete "routing" section — the provider's
// own list of what should bypass the tunnel. Which format arrives depends on the
// User-Agent the subscription was requested with; the same URL that returns a
// bare list of links to one client returns this to another.
func ParseXray(data []byte) ([]*model.Node, []SkipReason, *ProviderRules, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, nil, nil, fmt.Errorf("xray: %w", err)
	}

	outbounds := mList(doc, "outbounds")
	if len(outbounds) == 0 {
		return nil, nil, nil, fmt.Errorf("xray: document has no outbounds")
	}

	// A single-node config names the server in "remarks"; a multi-node one names
	// each outbound by tag.
	remarks := mStr(doc, "remarks")

	var (
		nodes   []*model.Node
		skipped []SkipReason
	)
	for i, ob := range outbounds {
		protocol := strings.ToLower(mStr(ob, "protocol"))
		tag := mStr(ob, "tag")

		// freedom and blackhole are Xray's own direct and block outbounds, not
		// servers anyone connects to.
		switch protocol {
		case "freedom", "blackhole", "dns", "":
			continue
		}

		node, err := xrayOutboundToNode(ob, protocol)
		if err != nil {
			skipped = append(skipped, SkipReason{
				Line: fmt.Sprintf("outbounds[%d] (%s)", i, protocol),
				Err:  err.Error(),
			})
			continue
		}
		if node.Name == "" {
			node.Name = orFirstNonEmpty(tag, node.Server)
		}
		nodes = append(nodes, node)
	}

	if len(nodes) == 0 {
		return nil, skipped, nil, fmt.Errorf("xray: no usable server outbounds")
	}

	// A config carrying one server names it in "remarks" and tags the outbound
	// with something generic like "proxy" — the remark is the name a person
	// recognizes, and it is what other clients display. With several servers the
	// tags are the meaningful part and the remark describes the whole document.
	if len(nodes) == 1 && remarks != "" {
		nodes[0].Name = remarks
	}
	for _, n := range nodes {
		n.AssignID()
	}
	return nodes, skipped, extractXrayRules(doc), nil
}

// xrayOutboundToNode converts one outbound into Obelisk's node model.
func xrayOutboundToNode(ob map[string]any, protocol string) (*model.Node, error) {
	settings := mMap(ob, "settings")
	n := &model.Node{Name: mStr(ob, "tag")}

	switch protocol {
	case "hysteria", "hysteria2", "hy2":
		stream := mMap(ob, "streamSettings")
		h := mMap(stream, "hysteriaSettings")
		if protocol == "hysteria" && mInt(settings, "version") != 2 {
			return nil, fmt.Errorf("only Hysteria version 2 is supported in Xray configurations")
		}
		n.Protocol = model.ProtoHysteria2
		n.Server = mStr(settings, "address")
		n.Port = mInt(settings, "port")
		n.Password = mStr(h, "auth")
		hop := mMap(h, "udphop")
		n.Hysteria = &model.HysteriaOpts{Ports: mStr(hop, "port"), HopInterval: mInt(hop, "interval")}
		mask := mMap(stream, "finalmask")
		for _, item := range mList(mask, "udp") {
			opts := mMap(item, "settings")
			if mStr(item, "type") != "salamander" || mStr(opts, "packetSize") != "" {
				return nil, fmt.Errorf("unsupported Hysteria2 UDP mask %q", mStr(item, "type"))
			}
			if n.Hysteria.Obfs != "" {
				return nil, fmt.Errorf("multiple Hysteria2 UDP masks are unsupported")
			}
			n.Hysteria.Obfs = "salamander"
			n.Hysteria.ObfsPassword = mStr(opts, "password")
		}
		if hop := mMap(mMap(mask, "quicParams"), "udpHop"); len(hop) > 0 {
			n.Hysteria.Ports = mStr(hop, "ports")
			n.Hysteria.HopInterval = mInt(hop, "interval")
		}
	case "trojan":
		servers := mList(settings, "servers")
		if len(servers) == 0 {
			return nil, fmt.Errorf("no servers listed")
		}
		s := servers[0]
		n.Protocol = model.ProtoTrojan
		n.Server = mStr(s, "address")
		n.Port = mInt(s, "port")
		n.Password = mStr(s, "password")

	case "vless", "vmess":
		vnext := mList(settings, "vnext")
		if len(vnext) == 0 {
			return nil, fmt.Errorf("no vnext listed")
		}
		v := vnext[0]
		users := mList(v, "users")
		if len(users) == 0 {
			return nil, fmt.Errorf("no users listed")
		}
		parsed, ok := model.ParseProtocol(protocol)
		if !ok {
			return nil, fmt.Errorf("unknown protocol %q", protocol)
		}
		n.Protocol = parsed
		n.Server = mStr(v, "address")
		n.Port = mInt(v, "port")
		n.UUID = mStr(users[0], "id")
		n.Flow = mStr(users[0], "flow")
		if protocol == "vmess" {
			n.AlterID = mInt(users[0], "alterId")
		}

	case "shadowsocks":
		servers := mList(settings, "servers")
		if len(servers) == 0 {
			return nil, fmt.Errorf("no servers listed")
		}
		s := servers[0]
		n.Protocol = model.ProtoShadowsocks
		n.Server = mStr(s, "address")
		n.Port = mInt(s, "port")
		n.Method = mStr(s, "method")
		n.Password = mStr(s, "password")

	default:
		return nil, fmt.Errorf("protocol %q is not supported in Xray configurations", protocol)
	}

	if n.Server == "" || n.Port == 0 {
		return nil, fmt.Errorf("no address")
	}
	applyXrayStream(n, mMap(ob, "streamSettings"))
	if n.Protocol == model.ProtoHysteria2 {
		n.Transport.Type = model.TransportQUIC
		n.TLS.Security = model.SecurityTLS
		if err := n.Validate(); err != nil {
			return nil, err
		}
	}
	return n, nil
}

// applyXrayStream maps streamSettings onto the transport and TLS model.
func applyXrayStream(n *model.Node, stream map[string]any) {
	if len(stream) == 0 {
		return
	}

	network := strings.ToLower(mStr(stream, "network"))
	switch network {
	case "", "tcp", "raw":
		n.Transport.Type = model.TransportTCP
	case "ws", "websocket":
		n.Transport.Type = model.TransportWebSocket
		ws := mMap(stream, "wsSettings")
		n.Transport.Path = mStr(ws, "path")
		if host := mStr(mMap(ws, "headers"), "Host"); host != "" {
			n.Transport.Host = []string{host}
		} else if host := mStr(ws, "host"); host != "" {
			n.Transport.Host = []string{host}
		}
	case "grpc":
		n.Transport.Type = model.TransportGRPC
		g := mMap(stream, "grpcSettings")
		n.Transport.ServiceName = mStr(g, "serviceName")
	case "http", "h2":
		n.Transport.Type = model.TransportHTTP
		h := mMap(stream, "httpSettings")
		n.Transport.Path = mStr(h, "path")
		n.Transport.Host = mStrSlice(h, "host")
	case "httpupgrade":
		n.Transport.Type = model.TransportHTTPUpgrade
		h := mMap(stream, "httpupgradeSettings")
		n.Transport.Path = mStr(h, "path")
		if host := mStr(h, "host"); host != "" {
			n.Transport.Host = []string{host}
		}
	case "xhttp", "splithttp":
		n.Transport.Type = model.TransportXHTTP
		x := mMap(stream, "xhttpSettings")
		if len(x) == 0 {
			x = mMap(stream, "splithttpSettings")
		}
		n.Transport.Path = mStr(x, "path")
		if host := mStr(x, "host"); host != "" {
			n.Transport.Host = []string{host}
		}
		n.Transport.XHTTPMode = mStr(x, "mode")
	case "kcp", "mkcp":
		n.Transport.Type = model.TransportKCP
		k := mMap(stream, "kcpSettings")
		n.Transport.Seed = mStr(k, "seed")
		n.Transport.HeaderType = mStr(mMap(k, "header"), "type")
	default:
		n.Transport.Type = model.Transport(network)
	}

	switch strings.ToLower(mStr(stream, "security")) {
	case "tls":
		n.TLS.Security = model.SecurityTLS
		t := mMap(stream, "tlsSettings")
		n.TLS.SNI = mStr(t, "serverName")
		n.TLS.Fingerprint = mStr(t, "fingerprint")
		n.TLS.ALPN = mStrSlice(t, "alpn")
		n.TLS.AllowInsecure = mBool(t, "allowInsecure")
	case "reality":
		n.TLS.Security = model.SecurityReality
		r := mMap(stream, "realitySettings")
		n.TLS.SNI = mStr(r, "serverName")
		n.TLS.Fingerprint = mStr(r, "fingerprint")
		n.TLS.PublicKey = mStr(r, "publicKey")
		n.TLS.ShortID = mStr(r, "shortId")
		n.TLS.SpiderX = mStr(r, "spiderX")
	default:
		n.TLS.Security = model.SecurityNone
	}
}

// extractXrayRules reads the routing section.
func extractXrayRules(doc map[string]any) *ProviderRules {
	out := &ProviderRules{}

	routingSection := mMap(doc, "routing")
	rules := mList(routingSection, "rules")
	if len(rules) == 0 {
		return out
	}

	sets := map[string]bool{}
	for i, rule := range rules {
		if strings.EqualFold(mStr(rule, "type"), "field") == false && mStr(rule, "type") != "" {
			continue
		}

		action := providerAction(mStr(rule, "outboundTag"))

		// A rule that matches on nothing but the network is the catch-all: it is
		// what happens to everything left over, which is the user's own setting
		// and not something to import.
		if len(mStrSlice(rule, "domain")) == 0 && len(mStrSlice(rule, "ip")) == 0 &&
			len(mStrSlice(rule, "protocol")) == 0 {
			continue
		}

		// Protocol rules match sniffed traffic types, which Obelisk's rule model
		// has no equivalent for.
		if protocols := mStrSlice(rule, "protocol"); len(protocols) > 0 &&
			len(mStrSlice(rule, "domain")) == 0 && len(mStrSlice(rule, "ip")) == 0 {
			out.Skipped = append(out.Skipped, SkipReason{
				Line: fmt.Sprintf("routing.rules[%d]", i),
				Err:  fmt.Sprintf("matches on protocol (%s), which is not importable", strings.Join(protocols, ", ")),
			})
			continue
		}

		for _, d := range mStrSlice(rule, "domain") {
			entry, set, err := xrayDomainEntry(d, action)
			if err != nil {
				out.Skipped = append(out.Skipped, SkipReason{
					Line: fmt.Sprintf("routing.rules[%d]: %s", i, truncate(d, 50)),
					Err:  err.Error(),
				})
				continue
			}
			if set != nil && !sets[set.Tag] {
				sets[set.Tag] = true
				out.RuleSets = append(out.RuleSets, *set)
			}
			out.Entries = append(out.Entries, *entry)
		}

		for _, ip := range mStrSlice(rule, "ip") {
			entry, set, err := xrayIPEntry(ip, action)
			if err != nil {
				out.Skipped = append(out.Skipped, SkipReason{
					Line: fmt.Sprintf("routing.rules[%d]: %s", i, truncate(ip, 50)),
					Err:  err.Error(),
				})
				continue
			}
			if set != nil && !sets[set.Tag] {
				sets[set.Tag] = true
				out.RuleSets = append(out.RuleSets, *set)
			}
			out.Entries = append(out.Entries, *entry)
		}
	}
	return out
}

// xrayDomainEntry converts one Xray domain matcher.
//
// Xray's prefixes are a small language of their own: "domain:" means the name
// and everything under it, "full:" means exactly that name, "regexp:" is a
// regular expression, "geosite:" names a category in the shared geo database,
// and a bare string is a substring match anywhere in the name.
func xrayDomainEntry(value string, action routing.Action) (*routing.Entry, *singbox.RuleSet, error) {
	prefix, rest, hasPrefix := strings.Cut(value, ":")
	if !hasPrefix {
		prefix, rest = "", value
	}

	var (
		entry = &routing.Entry{Raw: value, Action: action, Enabled: true}
		set   *singbox.RuleSet
	)

	switch strings.ToLower(prefix) {
	case "domain":
		entry.Kind = routing.KindDomainSuffix
		entry.Value = strings.ToLower(strings.TrimPrefix(rest, "."))
	case "full":
		entry.Kind = routing.KindDomainExact
		entry.Value = strings.ToLower(rest)
	case "regexp":
		entry.Kind = routing.KindDomainRegex
		entry.Value = rest
	case "geosite":
		tag, ruleSet, err := geoRuleSet("geosite", rest)
		if err != nil {
			return nil, nil, err
		}
		entry.Kind = routing.KindRuleSet
		entry.Value = tag
		set = ruleSet
	case "ext":
		return nil, nil, fmt.Errorf("refers to an external file on the provider's machine")
	default:
		// No recognised prefix: Xray treats a bare string as a substring match.
		entry.Kind = routing.KindDomainKeyword
		entry.Value = strings.ToLower(value)
		if strings.ContainsAny(entry.Value, " 	") {
			return nil, nil, fmt.Errorf("contains whitespace, which no domain does")
		}
	}

	if entry.Value == "" {
		return nil, nil, fmt.Errorf("empty value")
	}
	entry.Reindex()
	return entry, set, nil
}

// xrayIPEntry converts one Xray address matcher.
func xrayIPEntry(value string, action routing.Action) (*routing.Entry, *singbox.RuleSet, error) {
	if rest, ok := strings.CutPrefix(value, "geoip:"); ok {
		tag, set, err := geoRuleSet("geoip", rest)
		if err != nil {
			return nil, nil, err
		}
		entry := &routing.Entry{
			Raw: value, Kind: routing.KindRuleSet, Value: tag,
			Action: action, Enabled: true,
		}
		entry.Reindex()
		return entry, set, nil
	}
	if strings.HasPrefix(value, "ext:") {
		return nil, nil, fmt.Errorf("refers to an external file on the provider's machine")
	}

	// routing.ParseEntry already knows how to read an address or a subnet, and
	// having one implementation of that is worth more than saving a call.
	entry, err := routing.ParseEntry(value)
	if err != nil {
		return nil, nil, err
	}
	if entry.Kind != routing.KindIPCIDR {
		return nil, nil, fmt.Errorf("is not an address or subnet")
	}
	entry.Action = action
	entry.Reindex()
	return entry, nil, nil
}

// geoRuleSet turns a geosite or geoip category into a sing-box rule set.
//
// This is not a guess at what the provider meant. Xray's geosite.dat and
// geoip.dat are built from the v2fly community lists, and SagerNet publishes
// the same lists compiled into sing-box's own rule-set format from the same
// upstream data. Pointing at those is the identical set of domains in a
// different container, which is why it is safe to do here and would not have
// been safe to invent a mapping of our own.
func geoRuleSet(kind, category string) (string, *singbox.RuleSet, error) {
	category = strings.ToLower(strings.TrimSpace(category))
	if category == "" {
		return "", nil, fmt.Errorf("empty %s category", kind)
	}
	// Xray writes some categories with an "!" negation or "@attribute" suffix,
	// neither of which has a rule-set equivalent.
	if strings.ContainsAny(category, "!@") {
		return "", nil, fmt.Errorf("%s:%s uses an attribute or negation that has no equivalent", kind, category)
	}

	var repo string
	switch kind {
	case "geosite":
		repo = "sing-geosite"
	case "geoip":
		repo = "sing-geoip"
	default:
		return "", nil, fmt.Errorf("unknown geo database %q", kind)
	}

	tag := kind + "-" + category
	return tag, &singbox.RuleSet{
		Tag:            tag,
		Type:           "remote",
		Format:         "binary",
		URL:            fmt.Sprintf("https://raw.githubusercontent.com/SagerNet/%s/rule-set/%s.srs", repo, tag),
		UpdateInterval: "72h",
		// The lists are fetched through the tunnel, so that a network which
		// blocks the source cannot leave the router with no rules at all.
		DownloadDetour: "proxy",
	}, nil
}

// looksLikeXray reports whether a JSON document is an Xray configuration.
//
// Both cores use "outbounds", so the discriminator is what an outbound calls its
// kind: Xray says "protocol", sing-box says "type".
func looksLikeXray(doc map[string]any) bool {
	if _, ok := doc["routing"]; ok {
		return true
	}
	for _, ob := range mList(doc, "outbounds") {
		if _, ok := ob["protocol"]; ok {
			return true
		}
		if _, ok := ob["type"]; ok {
			return false
		}
	}
	return false
}

// orFirstNonEmpty returns the first value that is not empty.
func orFirstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
