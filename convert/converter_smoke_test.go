package convert

import (
	"reflect"
	"testing"
)

func TestHy2PortHopping(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want map[string]any // subset to check
	}{
		{
			name: "single port",
			url:  "hy2://pw@server.com:443/?sni=abc#n",
			want: map[string]any{"port": "443", "sni": "abc"},
		},
		{
			name: "port range",
			url:  "hy2://pw@server.com:443-500/#n",
			want: map[string]any{"port": "443", "ports": "443-500"},
		},
		{
			name: "port list",
			url:  "hy2://pw@server.com:443,600,700/?peer=fallback#n",
			want: map[string]any{"port": "443", "ports": "443,600,700", "sni": "fallback"},
		},
		{
			name: "range + list",
			url:  "hy2://pw@server.com:20000-30000,40000/?hop-interval=30s#n",
			want: map[string]any{"port": "20000", "ports": "20000-30000,40000", "hop-interval": "30s"},
		},
		{
			name: "mport only",
			url:  "hy2://pw@server.com:443/?mport=30000-40000#n",
			want: map[string]any{"port": "443", "ports": "30000-40000"},
		},
		{
			name: "ipv6 single port (should not trip regex)",
			url:  "hy2://pw@[::1]:443/#n",
			want: map[string]any{"port": "443"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxies, err := ConvertsV2Ray([]byte(tc.url))
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if len(proxies) != 1 {
				t.Fatalf("expected 1 proxy, got %d", len(proxies))
			}
			p := proxies[0]
			for k, v := range tc.want {
				got, ok := p[k]
				if !ok {
					t.Errorf("missing key %q in %+v", k, p)
					continue
				}
				if !reflect.DeepEqual(got, v) {
					t.Errorf("key %q: got %v, want %v", k, got, v)
				}
			}
		})
	}
}

func TestAnytlsExtraFields(t *testing.T) {
	url := "anytls://pw@server:443?sni=example.com&alpn=h2,http/1.1&fp=chrome&insecure=1&pbk=PBKVAL&sid=SID#n"
	proxies, err := ConvertsV2Ray([]byte(url))
	if err != nil || len(proxies) != 1 {
		t.Fatalf("parse failed: err=%v proxies=%+v", err, proxies)
	}
	p := proxies[0]
	if p["alpn"] == nil {
		t.Errorf("expected alpn set")
	}
	if p["client-fingerprint"] != "chrome" {
		t.Errorf("client-fingerprint: got %v, want chrome", p["client-fingerprint"])
	}
	if p["skip-cert-verify"] != true {
		t.Errorf("skip-cert-verify: got %v, want true", p["skip-cert-verify"])
	}
	if _, ok := p["reality-opts"]; ok {
		t.Errorf("reality-opts should be disabled (commented) but present: %v", p["reality-opts"])
	}
}

func TestTuicAllowInsecure(t *testing.T) {
	cases := []string{
		"tuic://uuid:pw@server:443?allow_insecure=1#n",
		"tuic://uuid:pw@server:443?allowInsecure=1#n",
		"tuic://uuid:pw@server:443?insecure=1#n",
	}
	for _, url := range cases {
		t.Run(url, func(t *testing.T) {
			proxies, err := ConvertsV2Ray([]byte(url))
			if err != nil || len(proxies) != 1 {
				t.Fatalf("parse failed: %v", err)
			}
			if proxies[0]["skip-cert-verify"] != true {
				t.Errorf("skip-cert-verify not set from %s", url)
			}
		})
	}
}

func TestTrojanReality(t *testing.T) {
	url := "trojan://pw@server:443?sni=abc&pbk=PBKVAL&sid=SID#n"
	proxies, err := ConvertsV2Ray([]byte(url))
	if err != nil || len(proxies) != 1 {
		t.Fatalf("parse failed: %v", err)
	}
	ro, ok := proxies[0]["reality-opts"].(map[string]any)
	if !ok {
		t.Fatalf("reality-opts missing or wrong type: %+v", proxies[0]["reality-opts"])
	}
	if ro["public-key"] != "PBKVAL" || ro["short-id"] != "SID" {
		t.Errorf("reality-opts wrong: %+v", ro)
	}
}

func TestTrojanWSHost(t *testing.T) {
	url := "trojan://pw@server:443?type=ws&host=ws.example.com&path=/p#n"
	proxies, err := ConvertsV2Ray([]byte(url))
	if err != nil || len(proxies) != 1 {
		t.Fatalf("parse failed: %v", err)
	}
	wsOpts, ok := proxies[0]["ws-opts"].(map[string]any)
	if !ok {
		t.Fatalf("ws-opts missing: %+v", proxies[0])
	}
	if wsOpts["path"] != "/p" {
		t.Errorf("ws path: got %v, want /p", wsOpts["path"])
	}
	headers, _ := wsOpts["headers"].(map[string]any)
	if headers["Host"] != "ws.example.com" {
		t.Errorf("ws Host: got %v, want ws.example.com", headers["Host"])
	}
}

func TestTuicP2(t *testing.T) {
	url := "tuic://uuid:pw@server:443?fast_open=1&reduce-rtt=1&congestion_control=bbr#n"
	proxies, err := ConvertsV2Ray([]byte(url))
	if err != nil || len(proxies) != 1 {
		t.Fatalf("parse failed: %v", err)
	}
	p := proxies[0]
	if p["fast-open"] != true {
		t.Errorf("fast-open: got %v, want true", p["fast-open"])
	}
	if p["reduce-rtt"] != true {
		t.Errorf("reduce-rtt: got %v, want true", p["reduce-rtt"])
	}
	if p["congestion-controller"] != "bbr" {
		t.Errorf("congestion-controller: got %v", p["congestion-controller"])
	}
}

func TestHy2TFO(t *testing.T) {
	url := "hy2://pw@server:443?fastopen=true#n"
	proxies, err := ConvertsV2Ray([]byte(url))
	if err != nil || len(proxies) != 1 {
		t.Fatalf("parse failed: %v", err)
	}
	if proxies[0]["tfo"] != true {
		t.Errorf("tfo: got %v, want true", proxies[0]["tfo"])
	}
}

func TestHy2AnonymousPortHopping(t *testing.T) {
	// No auth in URL, but port is a range — must still parse and emit `ports`.
	url := "hy2://server.com:443-500/#n"
	proxies, err := ConvertsV2Ray([]byte(url))
	if err != nil || len(proxies) != 1 {
		t.Fatalf("parse failed: err=%v proxies=%+v", err, proxies)
	}
	p := proxies[0]
	if p["port"] != "443" {
		t.Errorf("port: got %v, want 443", p["port"])
	}
	if p["ports"] != "443-500" {
		t.Errorf("ports: got %v, want 443-500", p["ports"])
	}
}

func TestAnytlsHpkpPcsFallback(t *testing.T) {
	// hpkp takes precedence when present.
	url := "anytls://pw@server:443?hpkp=OLDPIN&pcs=NEWPIN#n"
	proxies, _ := ConvertsV2Ray([]byte(url))
	if proxies[0]["fingerprint"] != "OLDPIN" {
		t.Errorf("hpkp preferred: got %v", proxies[0]["fingerprint"])
	}
	// When hpkp missing, fall back to pcs.
	url2 := "anytls://pw@server:443?pcs=NEWPIN#n"
	proxies2, _ := ConvertsV2Ray([]byte(url2))
	if proxies2[0]["fingerprint"] != "NEWPIN" {
		t.Errorf("pcs fallback: got %v", proxies2[0]["fingerprint"])
	}
}

func TestAnytlsNoUsernameField(t *testing.T) {
	// mihomo's AnyTLSOption has no `username` field — emitting it is dead data.
	url := "anytls://pw@server:443#n"
	proxies, _ := ConvertsV2Ray([]byte(url))
	if _, ok := proxies[0]["username"]; ok {
		t.Errorf("anytls must not emit username field: %+v", proxies[0])
	}
}

func TestTrojanAllowInsecureFalse(t *testing.T) {
	// allowInsecure=0 must not set skip-cert-verify.
	url := "trojan://pw@server:443?allowInsecure=0#n"
	proxies, _ := ConvertsV2Ray([]byte(url))
	if v, ok := proxies[0]["skip-cert-verify"]; ok && v == true {
		t.Errorf("skip-cert-verify should not be true for allowInsecure=0, got %v", v)
	}
}

func TestTuicBoolTolerant(t *testing.T) {
	// After unifying on ParseBool, `true` (lowercase) must work too — not just `1`.
	url := "tuic://uuid:pw@server:443?fast_open=true&reduce_rtt=TRUE&allow_insecure=true#n"
	proxies, err := ConvertsV2Ray([]byte(url))
	if err != nil || len(proxies) != 1 {
		t.Fatalf("parse failed: %v", err)
	}
	p := proxies[0]
	if p["fast-open"] != true {
		t.Errorf("fast-open (from fast_open=true): got %v", p["fast-open"])
	}
	if p["reduce-rtt"] != true {
		t.Errorf("reduce-rtt (from reduce_rtt=TRUE): got %v", p["reduce-rtt"])
	}
	if p["skip-cert-verify"] != true {
		t.Errorf("skip-cert-verify (from allow_insecure=true): got %v", p["skip-cert-verify"])
	}
}
