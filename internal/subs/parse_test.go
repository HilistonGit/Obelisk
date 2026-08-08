package subs

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/obelisk-project/obelisk/internal/model"
)

func TestParseVLESSReality(t *testing.T) {
	link := "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@example.com:443" +
		"?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome" +
		"&pbk=xNiWbVxvHDlG4qBKZmgLtSf-i9pJKZ0YnR5rWzJq_Xw&sid=6ba85179e30d4fc2" +
		"&type=tcp&flow=xtls-rprx-vision#RU%20Reality"

	n, err := ParseURI(link)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}

	if n.Name != "RU Reality" {
		t.Errorf("Name = %q, want %q", n.Name, "RU Reality")
	}
	if n.Protocol != model.ProtoVLESS {
		t.Errorf("Protocol = %q, want vless", n.Protocol)
	}
	if n.UUID != "d342d11e-d424-4583-b36e-524ab1f0afa4" {
		t.Errorf("UUID = %q", n.UUID)
	}
	if n.Port != 443 {
		t.Errorf("Port = %d, want 443", n.Port)
	}
	if n.TLS.Security != model.SecurityReality {
		t.Errorf("Security = %q, want reality", n.TLS.Security)
	}
	if n.TLS.PublicKey != "xNiWbVxvHDlG4qBKZmgLtSf-i9pJKZ0YnR5rWzJq_Xw" {
		t.Errorf("PublicKey = %q", n.TLS.PublicKey)
	}
	if n.TLS.ShortID != "6ba85179e30d4fc2" {
		t.Errorf("ShortID = %q", n.TLS.ShortID)
	}
	if n.TLS.SNI != "www.microsoft.com" {
		t.Errorf("SNI = %q", n.TLS.SNI)
	}
	if n.Flow != "xtls-rprx-vision" {
		t.Errorf("Flow = %q", n.Flow)
	}
	if n.Transport.Type != model.TransportTCP {
		t.Errorf("Transport = %q, want tcp", n.Transport.Type)
	}
	// "encryption=none" is the VLESS default and must not be mistaken for the
	// Xray-only post-quantum encryption extension.
	if n.TLS.Encryption != "" {
		t.Errorf("Encryption = %q, want empty", n.TLS.Encryption)
	}
}

func TestParseVMessBase64JSON(t *testing.T) {
	payload := `{"v":"2","ps":"NL WS","add":"nl.example.com","port":"443",
		"id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":0,"scy":"auto",
		"net":"ws","type":"none","host":"nl.example.com","path":"/vmess",
		"tls":"tls","sni":"nl.example.com","alpn":"h2,http/1.1","fp":"chrome"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))

	n, err := ParseURI(link)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}

	if n.Name != "NL WS" {
		t.Errorf("Name = %q", n.Name)
	}
	if n.Protocol != model.ProtoVMess {
		t.Errorf("Protocol = %q, want vmess", n.Protocol)
	}
	if n.Server != "nl.example.com" || n.Port != 443 {
		t.Errorf("address = %s", n.Address())
	}
	// "aid" arrives as a JSON number here and as a string elsewhere; both must
	// coerce to the same value.
	if n.AlterID != 0 {
		t.Errorf("AlterID = %d, want 0", n.AlterID)
	}
	if n.Transport.Type != model.TransportWebSocket {
		t.Errorf("Transport = %q, want ws", n.Transport.Type)
	}
	if n.Transport.Path != "/vmess" {
		t.Errorf("Path = %q", n.Transport.Path)
	}
	if len(n.Transport.Host) != 1 || n.Transport.Host[0] != "nl.example.com" {
		t.Errorf("Host = %v", n.Transport.Host)
	}
	if n.TLS.Security != model.SecurityTLS {
		t.Errorf("Security = %q, want tls", n.TLS.Security)
	}
	if len(n.TLS.ALPN) != 2 {
		t.Errorf("ALPN = %v, want two entries", n.TLS.ALPN)
	}
}

func TestParseVMessGRPCServiceNameFromPath(t *testing.T) {
	// The v2rayN dialect reuses "path" to carry the gRPC service name.
	payload := `{"v":"2","ps":"gRPC","add":"g.example.com","port":"443",
		"id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","net":"grpc",
		"path":"/GunService","tls":"tls"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))

	n, err := ParseURI(link)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if n.Transport.ServiceName != "GunService" {
		t.Errorf("ServiceName = %q, want GunService", n.Transport.ServiceName)
	}
	if n.Transport.Path != "" {
		t.Errorf("Path = %q, want empty once folded into ServiceName", n.Transport.Path)
	}
}

func TestParseTrojanImpliesTLS(t *testing.T) {
	// No "security" parameter: Trojan is TLS by definition.
	n, err := ParseURI("trojan://tr0janPass@tj.example.com:443?type=ws&path=%2Ftrojan#TJ")
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if n.Password != "tr0janPass" {
		t.Errorf("Password = %q", n.Password)
	}
	if n.TLS.Security != model.SecurityTLS {
		t.Errorf("Security = %q, want tls", n.TLS.Security)
	}
	if n.TLS.SNI != "tj.example.com" {
		t.Errorf("SNI = %q, want the server address as fallback", n.TLS.SNI)
	}
	if n.Transport.Path != "/trojan" {
		t.Errorf("Path = %q", n.Transport.Path)
	}
}

func TestParseShadowsocksDialects(t *testing.T) {
	tests := []struct {
		name       string
		link       string
		wantMethod string
		wantPass   string
		wantServer string
		wantPort   int
	}{
		{
			name:       "SIP002 base64 userinfo",
			link:       "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret123")) + "@ss.example.com:8388#SS",
			wantMethod: "aes-256-gcm",
			wantPass:   "secret123",
			wantServer: "ss.example.com",
			wantPort:   8388,
		},
		{
			name:       "legacy fully encoded",
			link:       "ss://" + base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pass@old.example.com:8443")) + "#Legacy",
			wantMethod: "chacha20-ietf-poly1305",
			wantPass:   "pass",
			wantServer: "old.example.com",
			wantPort:   8443,
		},
		{
			// A 2022 cipher's key is itself base64 and must survive verbatim.
			name:       "SS2022 plaintext userinfo",
			link:       "ss://2022-blake3-aes-128-gcm:UBhSVjZkNzc4a1BFMkFVaVpxTFE9PQ==@ss2.example.com:8388#SS2022",
			wantMethod: "2022-blake3-aes-128-gcm",
			wantPass:   "UBhSVjZkNzc4a1BFMkFVaVpxTFE9PQ==",
			wantServer: "ss2.example.com",
			wantPort:   8388,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n, err := ParseURI(tc.link)
			if err != nil {
				t.Fatalf("ParseURI: %v", err)
			}
			if n.Method != tc.wantMethod {
				t.Errorf("Method = %q, want %q", n.Method, tc.wantMethod)
			}
			if n.Password != tc.wantPass {
				t.Errorf("Password = %q, want %q", n.Password, tc.wantPass)
			}
			if n.Server != tc.wantServer || n.Port != tc.wantPort {
				t.Errorf("address = %s, want %s:%d", n.Address(), tc.wantServer, tc.wantPort)
			}
		})
	}
}

func TestParseShadowsocksPlugin(t *testing.T) {
	link := "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw")) +
		"@ss.example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#Obfs"

	n, err := ParseURI(link)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if n.Plugin != "obfs-local" {
		t.Errorf("Plugin = %q, want obfs-local", n.Plugin)
	}
	if n.PluginOpts != "obfs=http;obfs-host=bing.com" {
		t.Errorf("PluginOpts = %q", n.PluginOpts)
	}
	// A SIP003 plugin is implemented only by sing-box.
	if ok, _ := model.Supports(model.CoreXray, n); ok {
		t.Error("Xray must not claim support for a Shadowsocks plugin")
	}
	if ok, reason := model.Supports(model.CoreSingBox, n); !ok {
		t.Errorf("sing-box must support the plugin: %s", reason)
	}
}

func TestParseHysteria2(t *testing.T) {
	link := "hy2://s3cret@hy.example.com:8443?sni=hy.example.com&insecure=1" +
		"&obfs=salamander&obfs-password=obfspass&up=50&down=200#HY2"

	n, err := ParseURI(link)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if n.Protocol != model.ProtoHysteria2 {
		t.Errorf("Protocol = %q", n.Protocol)
	}
	if n.Password != "s3cret" {
		t.Errorf("Password = %q", n.Password)
	}
	if !n.TLS.AllowInsecure {
		t.Error("AllowInsecure = false, want true")
	}
	if n.Hysteria == nil {
		t.Fatal("Hysteria options are missing")
	}
	if n.Hysteria.Obfs != "salamander" || n.Hysteria.ObfsPassword != "obfspass" {
		t.Errorf("obfs = %q/%q", n.Hysteria.Obfs, n.Hysteria.ObfsPassword)
	}
	if n.Hysteria.UpMbps != 50 || n.Hysteria.DownMbps != 200 {
		t.Errorf("bandwidth = %d/%d", n.Hysteria.UpMbps, n.Hysteria.DownMbps)
	}
}

func TestParseHysteria2UserPassAuth(t *testing.T) {
	// Servers using userpass auth expect the credential spelled "user:password".
	n, err := ParseURI("hy2://alice:wonderland@hy.example.com:443#HY2")
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if n.Password != "alice:wonderland" {
		t.Errorf("auth = %q, want alice:wonderland", n.Password)
	}
}

func TestParseTUIC(t *testing.T) {
	link := "tuic://8c1f4b9e-2d3a-4f5b-9c8d-1e2f3a4b5c6d:tuicpass@tuic.example.com:443" +
		"?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tuic.example.com#TUIC"

	n, err := ParseURI(link)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if n.UUID != "8c1f4b9e-2d3a-4f5b-9c8d-1e2f3a4b5c6d" || n.Password != "tuicpass" {
		t.Errorf("credentials = %q / %q", n.UUID, n.Password)
	}
	if n.TUIC == nil || n.TUIC.CongestionControl != "bbr" {
		t.Errorf("TUIC options = %+v", n.TUIC)
	}
	if ok, _ := model.Supports(model.CoreXray, n); ok {
		t.Error("Xray must not claim TUIC support")
	}
}

func TestParseBase64Subscription(t *testing.T) {
	links := strings.Join([]string{
		"vless://d342d11e-d424-4583-b36e-524ab1f0afa4@a.example.com:443?security=tls&type=ws&path=/x#A",
		"trojan://pw@b.example.com:443#B",
		"hy2://pw@c.example.com:443#C",
		"this-line-is-garbage",
	}, "\n")
	payload := base64.StdEncoding.EncodeToString([]byte(links))

	res, err := Parse([]byte(payload))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Format != FormatBase64 {
		t.Errorf("Format = %q, want base64", res.Format)
	}
	if len(res.Nodes) != 3 {
		t.Fatalf("got %d nodes, want 3", len(res.Nodes))
	}
	// The malformed line must be reported rather than silently dropped.
	if len(res.Skipped) != 1 {
		t.Errorf("got %d skipped entries, want 1: %+v", len(res.Skipped), res.Skipped)
	}
}

func TestParseClash(t *testing.T) {
	doc := `
proxies:
  - name: "HK Trojan WS"
    type: trojan
    server: hk.example.com
    port: 443
    password: trojanpass
    network: ws
    ws-opts:
      path: /trojan
      headers:
        Host: hk.example.com
  - name: "JP Hysteria2"
    type: hysteria2
    server: jp.example.com
    port: 443
    password: hy2pass
    up: "50 Mbps"
    down: "200 Mbps"
    obfs: salamander
    obfs-password: obfspass
    sni: jp.example.com
  - name: "US VLESS Reality"
    type: vless
    server: us.example.com
    port: 443
    uuid: d342d11e-d424-4583-b36e-524ab1f0afa4
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    servername: www.microsoft.com
    reality-opts:
      public-key: xNiWbVxvHDlG4qBKZmgLtSf-i9pJKZ0YnR5rWzJq_Xw
      short-id: 6ba85179e30d4fc2
`
	res, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Format != FormatClash {
		t.Fatalf("Format = %q, want clash", res.Format)
	}
	if len(res.Nodes) != 3 {
		t.Fatalf("got %d nodes, want 3: %+v", len(res.Nodes), res.Skipped)
	}

	trojan := res.Nodes[0]
	if trojan.TLS.Security != model.SecurityTLS {
		t.Errorf("trojan Security = %q, want tls even without an explicit flag", trojan.TLS.Security)
	}
	if trojan.Transport.Path != "/trojan" {
		t.Errorf("trojan Path = %q", trojan.Transport.Path)
	}
	if len(trojan.Transport.Host) != 1 || trojan.Transport.Host[0] != "hk.example.com" {
		t.Errorf("trojan Host = %v", trojan.Transport.Host)
	}

	hy2 := res.Nodes[1]
	if hy2.Hysteria.UpMbps != 50 || hy2.Hysteria.DownMbps != 200 {
		t.Errorf("hysteria2 bandwidth = %d/%d, want 50/200", hy2.Hysteria.UpMbps, hy2.Hysteria.DownMbps)
	}

	vless := res.Nodes[2]
	if vless.TLS.Security != model.SecurityReality {
		t.Errorf("vless Security = %q, want reality", vless.TLS.Security)
	}
	if vless.TLS.ShortID != "6ba85179e30d4fc2" {
		t.Errorf("vless ShortID = %q", vless.TLS.ShortID)
	}
}

func TestParseSingBox(t *testing.T) {
	doc := `{
	  "outbounds": [
	    {"type": "direct", "tag": "direct"},
	    {"type": "selector", "tag": "proxy", "outbounds": ["a"]},
	    {
	      "type": "vless", "tag": "a",
	      "server": "a.example.com", "server_port": 443,
	      "uuid": "d342d11e-d424-4583-b36e-524ab1f0afa4",
	      "flow": "xtls-rprx-vision",
	      "tls": {
	        "enabled": true, "server_name": "www.microsoft.com",
	        "utls": {"enabled": true, "fingerprint": "chrome"},
	        "reality": {"enabled": true, "public_key": "PUBKEY", "short_id": "abcd"}
	      }
	    },
	    {
	      "type": "hysteria2", "tag": "b",
	      "server": "b.example.com", "server_port": 443,
	      "password": "pw", "up_mbps": 50, "down_mbps": 200,
	      "obfs": {"type": "salamander", "password": "obfspass"},
	      "tls": {"enabled": true, "server_name": "b.example.com"}
	    }
	  ]
	}`

	res, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if res.Format != FormatSingBox {
		t.Fatalf("Format = %q, want sing-box", res.Format)
	}
	// The direct and selector outbounds are policy, not servers.
	if len(res.Nodes) != 2 {
		t.Fatalf("got %d nodes, want 2: %+v", len(res.Nodes), res.Skipped)
	}

	if res.Nodes[0].TLS.Security != model.SecurityReality {
		t.Errorf("Security = %q, want reality", res.Nodes[0].TLS.Security)
	}
	if res.Nodes[0].TLS.Fingerprint != "chrome" {
		t.Errorf("Fingerprint = %q", res.Nodes[0].TLS.Fingerprint)
	}
	if res.Nodes[1].Hysteria.ObfsPassword != "obfspass" {
		t.Errorf("obfs password = %q", res.Nodes[1].Hysteria.ObfsPassword)
	}
}

func TestFingerprintIsStableAcrossRenames(t *testing.T) {
	base := "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@a.example.com:443?security=tls&type=ws&path=/x"

	first, err := ParseURI(base + "#Original Name")
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	renamed, err := ParseURI(base + "#🇳🇱 Renamed By Panel")
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}

	if first.ID != renamed.ID {
		t.Errorf("ID changed on rename: %s vs %s", first.ID, renamed.ID)
	}

	// A different path is a different configuration and must get a new ID.
	moved, err := ParseURI(strings.Replace(base, "path=/x", "path=/y", 1) + "#Original Name")
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	if first.ID == moved.ID {
		t.Error("ID must change when the transport path changes")
	}
}

func TestParseUserInfo(t *testing.T) {
	info := ParseUserInfo("upload=100; download=900; total=10000; expire=1767225600")
	if info == nil {
		t.Fatal("ParseUserInfo returned nil")
	}
	if info.Used() != 1000 {
		t.Errorf("Used = %d, want 1000", info.Used())
	}
	if info.Remaining() != 9000 {
		t.Errorf("Remaining = %d, want 9000", info.Remaining())
	}
	if info.Expire == nil || info.Expire.Year() != 2026 {
		t.Errorf("Expire = %v", info.Expire)
	}

	// An unmetered plan reports no total.
	unmetered := ParseUserInfo("upload=1; download=2")
	if unmetered.Remaining() != -1 {
		t.Errorf("Remaining = %d, want -1 for an unmetered plan", unmetered.Remaining())
	}

	if ParseUserInfo("") != nil {
		t.Error("an empty header must yield nil")
	}
}

func TestParseEmptyPayloadIsAnError(t *testing.T) {
	if _, err := Parse([]byte("   \n  ")); err == nil {
		t.Error("expected an error for an empty payload")
	}
}
