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
