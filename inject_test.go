package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"ublproxy/internal/blocklist"
)

func TestBootstrapScriptTagWithSession(t *testing.T) {
	sm := newSessionMap()
	sm.Set("192.168.1.10", sessionEntry{Token: "test-token-abc", CredentialID: "cred-1"})

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://192.168.1.1:8443",
	}

	tag := p.bootstrapScriptTag("192.168.1.10", "example.com")

	if !strings.Contains(tag, "<script>") {
		t.Error("should contain <script> tag")
	}
	if !strings.Contains(tag, "https://192.168.1.1:8443") {
		t.Error("should contain portal origin")
	}
	if !strings.Contains(tag, "test-token-abc") {
		t.Error("should contain session token")
	}
	if strings.Contains(tag, "__UBLPROXY_PORTAL__") {
		t.Error("should not contain template placeholder for portal")
	}
	if strings.Contains(tag, "__UBLPROXY_TOKEN__") {
		t.Error("should not contain template placeholder for token")
	}
	if strings.Contains(tag, "__UBLPROXY_HOST__") {
		t.Error("should not contain template placeholder for host")
	}
	if !strings.Contains(tag, "example.com") {
		t.Error("should contain the page host")
	}
}

func TestBootstrapScriptTagNoSession(t *testing.T) {
	sm := newSessionMap()

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://192.168.1.1:8443",
	}

	tag := p.bootstrapScriptTag("192.168.1.10", "example.com")
	if tag != "" {
		t.Errorf("should be empty for unknown IP, got: %s", tag)
	}
}

func TestScriptInjectionInHTML(t *testing.T) {
	sm := newSessionMap()
	sm.Set("127.0.0.1", sessionEntry{Token: "my-token", CredentialID: "cred-1"})

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://127.0.0.1:8443",
	}

	htmlBody := `<html><head><title>Test</title></head><body><p>Hello</p></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	modified, stats := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if !stats.Modified {
		t.Fatal("expected modification")
	}

	body := string(modified)
	if !strings.Contains(body, "<script>") {
		t.Error("should contain injected script tag")
	}
	if !strings.Contains(body, "my-token") {
		t.Error("should contain the session token")
	}
	if !strings.Contains(body, "https://127.0.0.1:8443") {
		t.Error("should contain the portal origin")
	}
	// Script should be before </body>
	scriptIdx := strings.Index(body, "<script>")
	bodyCloseIdx := strings.Index(body, "</body>")
	if scriptIdx >= bodyCloseIdx {
		t.Error("script should be injected before </body>")
	}
}

func TestNoScriptInjectionWithoutSession(t *testing.T) {
	sm := newSessionMap()

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://127.0.0.1:8443",
	}

	htmlBody := `<html><body><p>Hello</p></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	// No rules and no session -> no modification
	_, stats := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if stats.Modified {
		t.Error("should not modify HTML when there's no session and no rules")
	}
}

func TestScriptInjectionWithGzip(t *testing.T) {
	sm := newSessionMap()
	sm.Set("127.0.0.1", sessionEntry{Token: "gzip-token", CredentialID: "cred-1"})

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://127.0.0.1:8443",
	}

	htmlBody := `<html><body><p>Compressed</p></body></html>`
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(htmlBody))
	gz.Close()

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":     []string{"text/html"},
			"Content-Encoding": []string{"gzip"},
		},
		Body: io.NopCloser(&buf),
	}

	modified, stats := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if !stats.Modified {
		t.Fatal("expected modification for gzipped HTML")
	}

	body := string(modified)
	if !strings.Contains(body, "gzip-token") {
		t.Error("should contain the session token in decompressed output")
	}
}

func TestScriptInjectionWithRules(t *testing.T) {
	sm := newSessionMap()
	sm.Set("127.0.0.1", sessionEntry{Token: "rules-token", CredentialID: "cred-1"})

	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://127.0.0.1:8443",
	}
	p.baselineRules.Store(rs)

	htmlBody := `<html><head></head><body><div class="ad-banner">Ad</div><p>Content</p></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	modified, stats := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if !stats.Modified {
		t.Fatal("expected modification")
	}

	body := string(modified)

	// Element hiding via CSS and script injection should both work
	if !strings.Contains(body, "<style>") {
		t.Error("should contain CSS injection")
	}
	if !strings.Contains(body, ".ad-banner") {
		t.Error("CSS should contain the selector")
	}
	if !strings.Contains(body, "display: none !important") {
		t.Error("CSS should use display:none")
	}
	if !strings.Contains(body, "rules-token") {
		t.Error("should contain the session token")
	}
	// Content element should NOT be stripped from DOM (CSS-only hiding)
	if !strings.Contains(body, `class="ad-banner"`) {
		t.Error("content element should remain in DOM (hidden by CSS, not stripped)")
	}
}

func TestSessionMap(t *testing.T) {
	sm := newSessionMap()

	// Get from empty map
	if got := sm.Get("1.2.3.4"); got != nil {
		t.Errorf("Get empty = %v, want nil", got)
	}

	// Set and get
	sm.Set("1.2.3.4", sessionEntry{Token: "token-a", CredentialID: "cred-1"})
	if got := sm.Get("1.2.3.4"); got == nil || got.Token != "token-a" || got.CredentialID != "cred-1" {
		t.Errorf("Get = %v, want token-a/cred-1", got)
	}

	// Overwrite
	sm.Set("1.2.3.4", sessionEntry{Token: "token-b", CredentialID: "cred-2"})
	if got := sm.Get("1.2.3.4"); got == nil || got.Token != "token-b" || got.CredentialID != "cred-2" {
		t.Errorf("Get after overwrite = %v, want token-b/cred-2", got)
	}

	// Different IP
	if got := sm.Get("5.6.7.8"); got != nil {
		t.Errorf("Get different IP = %v, want nil", got)
	}

	// Delete
	sm.Delete("1.2.3.4")
	if got := sm.Get("1.2.3.4"); got != nil {
		t.Errorf("Get after delete = %v, want nil", got)
	}
}

func TestScriptInjectionWithZstd(t *testing.T) {
	sm := newSessionMap()
	sm.Set("127.0.0.1", sessionEntry{Token: "zstd-token", CredentialID: "cred-1"})

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://127.0.0.1:8443",
	}

	htmlBody := `<html><body><p>Zstd Compressed</p></body></html>`
	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	compressed := enc.EncodeAll([]byte(htmlBody), nil)
	enc.Close()

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":     []string{"text/html"},
			"Content-Encoding": []string{"zstd"},
		},
		Body: io.NopCloser(bytes.NewReader(compressed)),
	}

	modified, stats := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if !stats.Modified {
		t.Fatal("expected modification for zstd-compressed HTML")
	}

	body := string(modified)
	if !strings.Contains(body, "zstd-token") {
		t.Error("should contain the session token in decompressed output")
	}
	if !strings.Contains(body, "Zstd Compressed") {
		t.Error("should contain the original HTML content")
	}
}

func TestElementHidingStatsCountsSelectors(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")
	rs.AddLine("##.tracking-pixel")
	rs.AddLine("##.sponsored")

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	// HTML contains all three classes so all selectors match
	htmlBody := `<html><head></head><body>` +
		`<div class="ad-banner">Ad</div>` +
		`<img class="tracking-pixel">` +
		`<div class="sponsored">Promo</div>` +
		`</body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	_, stats := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if !stats.Modified {
		t.Fatal("expected modification")
	}
	if stats.Hidden != 3 {
		t.Errorf("Hidden = %d, want 3", stats.Hidden)
	}
	if stats.Stripped != 0 {
		t.Errorf("Stripped = %d, want 0", stats.Stripped)
	}
}

func TestElementHidingStatsCountsStripped(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("||ads.example.com^")
	rs.AddLine("||tracker.example.com^")

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	htmlBody := `<html><head>` +
		`<script src="https://ads.example.com/serve.js"></script>` +
		`</head><body>` +
		`<iframe src="https://tracker.example.com/frame"></iframe>` +
		`<p>Content</p>` +
		`</body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	_, stats := p.applyElementHiding(resp, "page.example.com", "127.0.0.1", false)
	if !stats.Modified {
		t.Fatal("expected modification")
	}
	if stats.Stripped != 2 {
		t.Errorf("Stripped = %d, want 2", stats.Stripped)
	}
}

func TestElementHidingStatsCombined(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")
	rs.AddLine("||ads.example.com^")

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	htmlBody := `<html><head>` +
		`<script src="https://ads.example.com/serve.js"></script>` +
		`</head><body>` +
		`<div class="ad-banner">Ad</div>` +
		`<p>Content</p>` +
		`</body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	_, stats := p.applyElementHiding(resp, "page.example.com", "127.0.0.1", false)
	if !stats.Modified {
		t.Fatal("expected modification")
	}
	if stats.Hidden != 1 {
		t.Errorf("Hidden = %d, want 1", stats.Hidden)
	}
	if stats.Stripped != 1 {
		t.Errorf("Stripped = %d, want 1", stats.Stripped)
	}

	want := "hidden=1; stripped=1; procedural=0"
	if got := stats.header(); got != want {
		t.Errorf("header() = %q, want %q", got, want)
	}
}

func TestElementHidingStatsNoModification(t *testing.T) {
	p := &proxyHandler{sessions: newSessionMap()}

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
	}

	_, stats := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if stats.Modified {
		t.Error("should not modify non-HTML response")
	}
	if stats.Hidden != 0 || stats.Stripped != 0 {
		t.Errorf("stats should be zero for unmodified response, got hidden=%d stripped=%d", stats.Hidden, stats.Stripped)
	}
}

func TestElementHidingFiltersUnmatchedSelectors(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("##.ad-banner")      // matches
	rs.AddLine("##.tracking-pixel") // no match — class not in HTML
	rs.AddLine("##.sponsored")      // no match
	rs.AddLine("##.augl")           // matches
	rs.AddLine("###slot-668")       // matches
	rs.AddLine("##.nonexistent")    // no match

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	htmlBody := `<html><head></head><body>` +
		`<div class="ad-banner">Ad</div>` +
		`<aside class="augl" id="slot-668">Augl</aside>` +
		`<p>Content</p>` +
		`</body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	modified, stats := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if !stats.Modified {
		t.Fatal("expected modification")
	}
	// Only 3 selectors match the HTML (ad-banner, augl, #slot-668)
	if stats.Hidden != 3 {
		t.Errorf("Hidden = %d, want 3", stats.Hidden)
	}

	body := string(modified)
	// Matching selectors should be in the CSS
	if !strings.Contains(body, ".ad-banner") {
		t.Error("CSS should contain .ad-banner")
	}
	if !strings.Contains(body, ".augl") {
		t.Error("CSS should contain .augl")
	}
	if !strings.Contains(body, "#slot-668") {
		t.Error("CSS should contain #slot-668")
	}
	// Non-matching selectors should NOT be in the CSS
	if strings.Contains(body, ".tracking-pixel") {
		t.Error("CSS should NOT contain .tracking-pixel (not in HTML)")
	}
	if strings.Contains(body, ".sponsored") {
		t.Error("CSS should NOT contain .sponsored (not in HTML)")
	}
	if strings.Contains(body, ".nonexistent") {
		t.Error("CSS should NOT contain .nonexistent (not in HTML)")
	}
}

func TestScriptletInjection(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("example.com##+js(nowebrtc)")
	rs.AddLine("example.com##+js(set-constant, ads.enabled, true)")

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	htmlBody := `<html><head><title>Test</title></head><body><p>Content</p></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	modified, stats := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if !stats.Modified {
		t.Fatal("expected modification for scriptlet injection")
	}

	body := string(modified)

	// Both scriptlets should be injected as <script> tags
	if !strings.Contains(body, "RTCPeerConnection") {
		t.Error("should contain nowebrtc scriptlet (RTCPeerConnection)")
	}
	if !strings.Contains(body, "ads.enabled") {
		t.Error("should contain set-constant scriptlet for ads.enabled")
	}

	// Scriptlets must run before the page's own inline scripts, not just
	// somewhere in the head. YouTube sets ytcfg and runs its anti-adblock
	// checks in head inline scripts, so landing after them is too late.
	headOpenIdx := strings.Index(body, "<head>")
	headCloseIdx := strings.Index(body, "</head>")
	if headOpenIdx < 0 || headCloseIdx < 0 {
		t.Fatal("should still have head tags")
	}
	rtcIdx := strings.Index(body, "RTCPeerConnection")
	if rtcIdx < headOpenIdx || rtcIdx > headCloseIdx {
		t.Error("scriptlets should be injected inside <head>, before any page script")
	}
	// Ahead of the page's own inline script in the head.
	titleIdx := strings.Index(body, "<title>")
	if titleIdx >= 0 && rtcIdx > titleIdx {
		t.Error("scriptlets should be injected before the page's first inline head script")
	}
}

func TestInjectAtDocumentStart(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{"after head open", `<html><head><title>T</title></head><body></body></html>`, `<html><head>[X]<title>T</title></head><body></body></html>`},
		{"head with attributes", `<html><head data-a="b"><title>T</title></head>`, `<html><head data-a="b">[X]<title>T</title></head>`},
		{"gt inside attribute", `<html><head data-a="a>b"><title>T</title></head>`, `<html><head data-a="a>b">[X]<title>T</title></head>`},
		{"self closing head", `<html><head/><body></body></html>`, `<html><head/>[X]<body></body></html>`},
		// "<header>" must not be mistaken for a head tag.
		{"no head, falls back to html", `<html><body><header>hi</header></body></html>`, `<html>[X]<body><header>hi</header></body></html>`},
		{"uppercase", `<HTML><HEAD><title>T</title></HEAD>`, `<HTML><HEAD>[X]<title>T</title></HEAD>`},
		{"no head no html", `<body><p>x</p></body>`, `<body><p>x</p>[X]</body>`},
		{"bare fragment", `<p>hi</p>`, `<p>hi</p>[X]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(injectAtDocumentStart([]byte(tt.html), []byte("[X]")))
			if got != tt.want {
				t.Errorf("injectAtDocumentStart\n got: %s\nwant: %s", got, tt.want)
			}
		})
	}
}

func TestDomainScopedSelectorsSurviveServerSideFilter(t *testing.T) {
	rs := blocklist.NewRuleSet()
	// A Polymer app builds these after the HTML was served, so the class is
	// nowhere in the server's markup.
	rs.AddLine("youtube.com##.ytp-ad-module")
	rs.AddLine("youtube.com##ytd-ad-slot-renderer")
	rs.AddLine("youtube.com##ytd-rich-item-renderer:has(> ytd-ad-slot-renderer)")
	// A generic rule that genuinely cannot match should still be dropped.
	rs.AddLine("##.never-in-any-html")

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	htmlBody := `<html><head></head><body><ytd-app></ytd-app></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	modified, stats := p.applyElementHiding(resp, "youtube.com", "127.0.0.1", false)
	if !stats.Modified {
		t.Fatal("expected modification")
	}

	body := string(modified)
	for _, sel := range []string{
		".ytp-ad-module",
		"ytd-ad-slot-renderer",
		"ytd-rich-item-renderer:has(> ytd-ad-slot-renderer)",
	} {
		if !strings.Contains(body, sel) {
			t.Errorf("domain-scoped selector %q was dropped by the server-side pre-filter", sel)
		}
	}
	if strings.Contains(body, ".never-in-any-html") {
		t.Error("generic selector with no match should still be filtered out")
	}
}

func TestDuplicateSelectorsInjectedOnce(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("example.com##.ad-banner")
	rs.AddLine("example.com##.ad-banner")

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	htmlBody := `<html><head></head><body><div class="ad-banner">Ad</div></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	modified, _ := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if n := strings.Count(string(modified), ".ad-banner"); n != 1 {
		t.Errorf("selector injected %d times, want 1", n)
	}
}

func TestScriptletInjectionNoMatchingDomain(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("other.com##+js(nowebrtc)")

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	htmlBody := `<html><head></head><body><p>Content</p></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	// No scriptlets match example.com, and no CSS rules either
	_, stats := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if stats.Modified {
		t.Error("should not modify when no scriptlets or rules match the domain")
	}
}

func TestScriptletInjectionSanitizesScriptClose(t *testing.T) {
	rs := blocklist.NewRuleSet()
	// Argument contains </script> which must be escaped
	rs.AddLine(`example.com##+js(set-constant, x</script>, true)`)

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	htmlBody := `<html><head></head><body><p>Content</p></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	modified, _ := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	body := string(modified)

	// Must not contain raw </script> inside the scriptlet injection
	// (the closing </script> of the wrapper tag is OK, but not inside the JS)
	scriptStart := strings.Index(body, "<script>")
	scriptEnd := strings.Index(body, "</script>")
	if scriptStart >= 0 && scriptEnd > scriptStart {
		jsContent := body[scriptStart+len("<script>") : scriptEnd]
		if strings.Contains(jsContent, "</script") {
			t.Error("scriptlet JS must not contain unescaped </script>")
		}
	}
}

func TestScriptletInjectionWithCSSRules(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("example.com##+js(nowebrtc)")
	rs.AddLine("##.ad-banner")

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	htmlBody := `<html><head></head><body><div class="ad-banner">Ad</div><p>Content</p></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	modified, stats := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if !stats.Modified {
		t.Fatal("expected modification")
	}

	body := string(modified)

	// Both CSS and scriptlet should be present
	if !strings.Contains(body, "<style>") {
		t.Error("should contain CSS style tag")
	}
	if !strings.Contains(body, ".ad-banner") {
		t.Error("should contain CSS selector")
	}
	if !strings.Contains(body, "RTCPeerConnection") {
		t.Error("should contain scriptlet injection")
	}
}

func TestScriptletInjectionFromUserRules(t *testing.T) {
	// User rules should also provide scriptlets
	userRS := blocklist.NewRuleSet()
	userRS.AddLine("example.com##+js(nowebrtc)")

	sm := newSessionMap()
	sm.Set("127.0.0.1", sessionEntry{Token: "tok", CredentialID: "cred-1"})

	p := &proxyHandler{
		sessions:     sm,
		portalOrigin: "https://127.0.0.1:8443",
	}
	p.userRules.Store("cred-1", userRS)

	htmlBody := `<html><head></head><body><p>Content</p></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	modified, stats := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if !stats.Modified {
		t.Fatal("expected modification from user scriptlets")
	}

	body := string(modified)
	if !strings.Contains(body, "RTCPeerConnection") {
		t.Error("should contain scriptlet from user rules")
	}
}

func TestProceduralRemovesNodeEndToEnd(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("page.example.com#?#.ad:remove()")

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	htmlBody := `<html><head></head><body>` +
		`<div class="ad"><p>Ad</p></div>` +
		`<div class="post">Content</div>` +
		`</body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	body, stats := p.applyElementHiding(resp, "page.example.com", "127.0.0.1", false)
	if stats.Procedural != 1 {
		t.Errorf("Procedural = %d, want 1", stats.Procedural)
	}
	got := string(body)
	if strings.Contains(got, "Ad") {
		t.Errorf("matched node should be gone, got: %s", got)
	}
	if !strings.Contains(got, "Content") {
		t.Error("unrelated content should survive")
	}
}

func TestProceduralNoMatchLeavesBytesAlone(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("page.example.com#?#.ad:remove()")

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	// Deliberately un-normalized markup. A rule that matches nothing must not
	// trigger a parse/render round trip, so these bytes reach the client as-is.
	htmlBody := `<html><head><meta charset=utf-8></head><body><img src=a.png><p>Hi</p></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	body, stats := p.applyElementHiding(resp, "page.example.com", "127.0.0.1", false)
	if stats.Procedural != 0 {
		t.Errorf("Procedural = %d, want 0", stats.Procedural)
	}
	if got := string(body); got != htmlBody {
		t.Errorf("body was rewritten with no match:\n got: %s\nwant: %s", got, htmlBody)
	}
}

func TestProceduralNoActionEmitsMarkerCSS(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("page.example.com#?#div:has-text(Sponsored)")

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	htmlBody := `<html><head></head><body><div>Ad <span>Sponsored</span></div><div>Real</div></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	body, _ := p.applyElementHiding(resp, "page.example.com", "127.0.0.1", false)
	got := string(body)
	if !strings.Contains(got, "display: none !important") {
		t.Errorf("expected marker CSS, got: %s", got)
	}
	if !strings.Contains(got, "ublp-phid") {
		t.Errorf("matched node should carry the marker class, got: %s", got)
	}
	// Both divs are present, so hydration sees the same shape it would without
	// the rule; the class plus CSS does the hiding.
	if strings.Count(got, "<div") != 2 {
		t.Errorf("no-action rule should not remove nodes, got: %s", got)
	}
}

func TestProceduralSkippedForOtherHost(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("youtube.com#?#.ad:remove()")

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	htmlBody := `<html><head></head><body><div class="ad">Ad</div></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	body, stats := p.applyElementHiding(resp, "other.example", "127.0.0.1", false)
	if stats.Procedural != 0 {
		t.Errorf("Procedural = %d, want 0 for a host with no rules", stats.Procedural)
	}
	if got := string(body); got != htmlBody {
		t.Errorf("body should be untouched:\n got: %s\nwant: %s", got, htmlBody)
	}
}

func TestProceduralRoundTripPreservesScripts(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine("page.example.com#?#.ad:remove()")

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	// YouTube-shaped markup. Script bodies, doctype and entities have to
	// survive verbatim or hydration breaks.
	htmlBody := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<script nonce="n1">var ytcfg={};if (1<2){ytcfg.set({a:"b<c"});}</script>` +
		`</head><body><div id="content"><ytd-ad-slot-renderer class="ad"></ytd-ad-slot-renderer>` +
		`<p>a &amp; b &lt;c&gt;</p></div>` +
		`<script nonce="n2">window.jslib=1;</script></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(htmlBody)),
	}

	body, stats := p.applyElementHiding(resp, "page.example.com", "127.0.0.1", false)
	if stats.Procedural != 1 {
		t.Fatalf("Procedural = %d, want 1", stats.Procedural)
	}
	got := string(body)
	for _, want := range []string{
		"<!DOCTYPE html>",
		`if (1<2){ytcfg.set({a:"b<c"});}`,
		"window.jslib=1;",
		"a &amp; b &lt;c&gt;",
		`nonce="n1"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("round trip lost %q:\n%s", want, got)
		}
	}
}

// The three rules this whole effort started from, against YouTube-shaped
// markup. The first two are CSS and work today; #?# is the server-side path
// for the ad slot when the page ships it in the initial HTML.
func TestYouTubeAdSlotRemoval(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine(`youtube.com##ytd-ad-slot-renderer`)
	rs.AddLine(`youtube.com##ytd-rich-item-renderer:has(> ytd-ad-slot-renderer)`)
	rs.AddLine(`youtube.com#?#ytd-rich-item-renderer:has(> ytd-ad-slot-renderer):remove()`)
	rs.AddLine(`youtube.com#?##^script:has-text(adPlacements)`)

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	body := `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>YouTube</title>` +
		`<script nonce="a">var ytcfg = ytcfg || {};ytcfg.set({INNERTUBE_CLIENT_VERSION:"2.2"});</script>` +
		`</head><body><ytd-app>` +
		`<ytd-rich-item-renderer><ytd-ad-slot-renderer class="ad-slot"></ytd-ad-slot-renderer>` +
		`<div id="video-title">Real Video</div></ytd-rich-item-renderer>` +
		`<ytd-rich-item-renderer><div id="video-title">Another Video</div></ytd-rich-item-renderer>` +
		`</ytd-app></body></html>`

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}

	out, stats := p.applyElementHiding(resp, "www.youtube.com", "127.0.0.1", false)
	got := string(out)

	// The ad-carrying rich item is gone; the real one stays.
	if strings.Contains(got, "Real Video") {
		t.Errorf("ad-carrying rich item should be removed:\n%s", got)
	}
	if !strings.Contains(got, "Another Video") {
		t.Errorf("real video should survive:\n%s", got)
	}
	// Both rules still emit their CSS for nodes built client-side.
	if !strings.Contains(got, "ytd-ad-slot-renderer") {
		t.Error("CSS rule should still be injected")
	}
	// Script bodies must survive the round trip verbatim.
	if !strings.Contains(got, `ytcfg.set({INNERTUBE_CLIENT_VERSION:"2.2"});`) {
		t.Errorf("inline script was damaged:\n%s", got)
	}
	if stats.Procedural == 0 {
		t.Error("expected procedural rules to act")
	}
}

// YouTube assigns the player's ad schedule as an inline object literal, so
// json-prune has to install its hook before that assignment runs. Ordering is
// the whole game here: installed a moment later it is useless.
func TestJsonPruneHookPrecedesInlinePlayerResponse(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine(`www.youtube.com##+js(json-prune, adPlacements playerAds)`)

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	body := `<html><head></head><body>` +
		`<script nonce="x">var ytInitialPlayerResponse = {"adPlacements":[{"a":1}]};</script>` +
		`</body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}

	out, _ := p.applyElementHiding(resp, "www.youtube.com", "127.0.0.1", false)
	got := string(out)

	hookAt := strings.Index(got, "Object.defineProperty(window, 'ytInitialPlayerResponse'")
	assignAt := strings.Index(got, "var ytInitialPlayerResponse")
	if hookAt < 0 {
		t.Fatalf("hook was not injected:\n%s", got)
	}
	if assignAt < 0 {
		t.Fatalf("page script missing from output:\n%s", got)
	}
	if hookAt > assignAt {
		t.Errorf("hook must be installed before the page assigns it (hook@%d, assign@%d):\n%s",
			hookAt, assignAt, got)
	}
}

// uBlock's rule lists both the wrapped and the bare form of the ad paths. The
// needle argument is optional in json-prune, so with a single argument there is
// no precondition and each listed path is pruned from whatever payload carries
// it. Listing both forms is deliberate, not self-defeating.
func TestJsonPruneRuleForInlinePlayerResponse(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine(`www.youtube.com##+js(json-prune, adPlacements playerAds adSlots)`)

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	watchPage := `<html><head></head><body><script nonce="x">var ytInitialPlayerResponse = ` +
		`{"adPlacements":[{"adPlacementRenderer":{"config":{"adPlacementConfig":` +
		`{"kind":"AD_PLACEMENT_KIND_START"}}}}],"videoDetails":{"videoId":"abc"},` +
		`"streamingData":{"expiresInSeconds":"21540"}};</script></body></html>`

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(watchPage)),
	}
	out, _ := p.applyElementHiding(resp, "www.youtube.com", "127.0.0.1", false)
	got := string(out)

	hook := "Object.defineProperty(window, 'ytInitialPlayerResponse'"
	hookAt := strings.Index(got, hook)
	assignAt := strings.Index(got, "var ytInitialPlayerResponse")
	if hookAt < 0 {
		t.Fatalf("inline-response hook missing:\n%s", got)
	}
	if hookAt > assignAt {
		t.Errorf("hook@%d must precede the page's assignment@%d", hookAt, assignAt)
	}
	// The proxy must not rewrite the page's own script; pruning happens in the
	// browser, not in the bytes on the wire.
	if !strings.Contains(got, "AD_PLACEMENT_KIND_START") {
		t.Error("page script should pass through untouched")
	}
}

// A CSP nonce in the response makes 'unsafe-inline' inert, so an injected
// inline script without that nonce is blocked and the scriptlet silently never
// runs. This is what killed every ##+js() rule on YouTube. Reusing the page's
// own nonce works because we are rewriting that same response.
func TestScriptletInjectionCarriesPageCSPNonce(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine(`www.youtube.com##+js(json-prune, adPlacements)`)

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	body := `<html><head><script nonce="gmtL5wrq9y9E5TLmgdIVzA">var a=1;</script></head>` +
		`<body></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}

	out, _ := p.applyElementHiding(resp, "www.youtube.com", "127.0.0.1", false)
	got := string(out)

	hookAt := strings.Index(got, "prunePaths")
	if hookAt < 0 {
		t.Fatalf("scriptlet not injected:\n%s", got)
	}
	open := got[:hookAt]
	lastOpen := strings.LastIndex(open, "<script")
	tag := got[lastOpen : lastOpen+strings.Index(got[lastOpen:], ">")+1]
	if !strings.Contains(tag, `nonce="gmtL5wrq9y9E5TLmgdIVzA"`) {
		t.Errorf("injected script needs the page's CSP nonce, got tag: %s", tag)
	}
	if strings.Index(tag, "nonce=") > strings.Index(tag, ">") {
		t.Errorf("nonce must be an attribute of the script tag, got: %s", tag)
	}
}

// Pages without a CSP nonce must still get a plain script tag.
func TestScriptletInjectionWithoutCSPNonce(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine(`example.com##+js(json-prune, adPlacements)`)

	p := &proxyHandler{sessions: newSessionMap()}
	p.baselineRules.Store(rs)

	body := `<html><head><script>var a=1;</script></head><body></body></html>`
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}

	out, _ := p.applyElementHiding(resp, "example.com", "127.0.0.1", false)
	if strings.Contains(string(out), "nonce=") {
		t.Errorf("must not invent a nonce when the page has none:\n%s", out)
	}
}
