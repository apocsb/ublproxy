package blocklist_test

import (
	"strings"
	"testing"

	"ublproxy/internal/blocklist"
)

func TestScriptletSourceUnknown(t *testing.T) {
	got := blocklist.ScriptletSource("nonexistent-scriptlet", nil)
	if got != "" {
		t.Errorf("unknown scriptlet should return empty string, got %q", got)
	}
}

func TestScriptletSourceAliases(t *testing.T) {
	tests := []struct {
		alias     string
		canonical string
		args      []string
	}{
		{"set", "set-constant", []string{"ads", "true"}},
		{"aopr", "abort-on-property-read", []string{"detectAdBlock"}},
		{"aopw", "abort-on-property-write", []string{"adblock"}},
		{"acis", "abort-current-inline-script", []string{"eval"}},
		{"aeld", "addEventListener-defuser", []string{"click"}},
		{"ra", "remove-attr", []string{"onclick"}},
		{"rc", "remove-class", []string{"ad", "div"}},
	}

	for _, tt := range tests {
		aliasResult := blocklist.ScriptletSource(tt.alias, tt.args)
		canonicalResult := blocklist.ScriptletSource(tt.canonical, tt.args)
		if aliasResult == "" {
			t.Errorf("alias %q returned empty string", tt.alias)
			continue
		}
		if aliasResult != canonicalResult {
			t.Errorf("alias %q produced different output than canonical %q", tt.alias, tt.canonical)
		}
	}
}

// An alias pointing at a scriptlet that doesn't exist resolves to an empty
// string, which silently turns every filter using it into a no-op.
func TestEveryAliasResolvesToAnImplementedScriptlet(t *testing.T) {
	for _, alias := range blocklist.ScriptletAliases() {
		if blocklist.ScriptletSource(alias, []string{"probe-arg", "true"}) == "" {
			t.Errorf("alias %q has no matching scriptlet in the library", alias)
		}
	}
}

func TestScriptletSourceSetConstant(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		contains []string
		empty    bool
	}{
		{
			name:  "too few args",
			args:  []string{"ads"},
			empty: true,
		},
		{
			name:     "basic true",
			args:     []string{"ads.enabled", "true"},
			contains: []string{"ads.enabled", "value = true"},
		},
		{
			name:     "noopFunc",
			args:     []string{"check", "noopFunc"},
			contains: []string{"check", "(function(){})"},
		},
		{
			name:     "trueFunc",
			args:     []string{"check", "trueFunc"},
			contains: []string{"check", "(function(){return true})"},
		},
		{
			name:     "falseFunc",
			args:     []string{"check", "falseFunc"},
			contains: []string{"check", "(function(){return false})"},
		},
		{
			name:     "undefined",
			args:     []string{"prop", "undefined"},
			contains: []string{"value = undefined"},
		},
		{
			name:     "empty string",
			args:     []string{"prop", "''"},
			contains: []string{"value = ''"},
		},
		{
			name:     "zero",
			args:     []string{"prop", "0"},
			contains: []string{"value = 0"},
		},
		{
			name:     "custom string fallback",
			args:     []string{"prop", "hello"},
			contains: []string{"value = 'hello'"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := blocklist.ScriptletSource("set-constant", tt.args)
			if tt.empty {
				if got != "" {
					t.Errorf("expected empty, got %q", got)
				}
				return
			}
			if got == "" {
				t.Fatal("expected non-empty output")
			}
			for _, s := range tt.contains {
				if !strings.Contains(got, s) {
					t.Errorf("output should contain %q, got:\n%s", s, got)
				}
			}
		})
	}
}

func TestScriptletSourceAbortOnPropertyRead(t *testing.T) {
	got := blocklist.ScriptletSource("abort-on-property-read", []string{"detectAdBlock"})
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if !strings.Contains(got, "detectAdBlock") {
		t.Error("should contain the property name")
	}
	if !strings.Contains(got, "ReferenceError") {
		t.Error("should throw ReferenceError")
	}

	// No args
	if blocklist.ScriptletSource("abort-on-property-read", nil) != "" {
		t.Error("should return empty with no args")
	}
}

func TestScriptletSourceAbortOnPropertyWrite(t *testing.T) {
	got := blocklist.ScriptletSource("abort-on-property-write", []string{"adblock"})
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if !strings.Contains(got, "adblock") {
		t.Error("should contain the property name")
	}
	if !strings.Contains(got, "set: function()") {
		t.Error("should define a setter trap")
	}

	if blocklist.ScriptletSource("abort-on-property-write", nil) != "" {
		t.Error("should return empty with no args")
	}
}

func TestScriptletSourceAbortCurrentInlineScript(t *testing.T) {
	// With needle
	got := blocklist.ScriptletSource("abort-current-inline-script", []string{"eval", "ads"})
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if !strings.Contains(got, "eval") {
		t.Error("should contain the property name")
	}
	if !strings.Contains(got, "ads") {
		t.Error("should contain the needle")
	}
	if !strings.Contains(got, "document.currentScript") {
		t.Error("should check document.currentScript")
	}

	// Without needle
	got = blocklist.ScriptletSource("abort-current-inline-script", []string{"eval"})
	if got == "" {
		t.Fatal("expected non-empty output without needle")
	}
	if !strings.Contains(got, "needle = ''") {
		t.Error("needle should be empty string when not provided")
	}

	if blocklist.ScriptletSource("abort-current-inline-script", nil) != "" {
		t.Error("should return empty with no args")
	}
}

func TestScriptletSourceAddEventListenerDefuser(t *testing.T) {
	// Both args
	got := blocklist.ScriptletSource("addEventListener-defuser", []string{"click", "trackClick"})
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if !strings.Contains(got, "click") {
		t.Error("should contain type needle")
	}
	if !strings.Contains(got, "trackClick") {
		t.Error("should contain handler needle")
	}
	if !strings.Contains(got, "EventTarget.prototype.addEventListener") {
		t.Error("should patch addEventListener")
	}

	// No args (matches all)
	got = blocklist.ScriptletSource("addEventListener-defuser", nil)
	if got == "" {
		t.Fatal("should work with no args")
	}
}

func TestScriptletSourceNowebrtc(t *testing.T) {
	got := blocklist.ScriptletSource("nowebrtc", nil)
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if !strings.Contains(got, "RTCPeerConnection") {
		t.Error("should block RTCPeerConnection")
	}
	if !strings.Contains(got, "webkitRTCPeerConnection") {
		t.Error("should block webkitRTCPeerConnection")
	}
}

func TestScriptletSourceNoSetTimeoutIf(t *testing.T) {
	got := blocklist.ScriptletSource("no-setTimeout-if", []string{"ads", "1000"})
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if !strings.Contains(got, "ads") {
		t.Error("should contain needle")
	}
	if !strings.Contains(got, "1000") {
		t.Error("should contain delay")
	}
	if !strings.Contains(got, "window.setTimeout") {
		t.Error("should patch setTimeout")
	}

	// No args
	got = blocklist.ScriptletSource("no-setTimeout-if", nil)
	if got == "" {
		t.Fatal("should work with no args")
	}
}

func TestScriptletSourceNoSetIntervalIf(t *testing.T) {
	got := blocklist.ScriptletSource("no-setInterval-if", []string{"ping", "5000"})
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if !strings.Contains(got, "ping") {
		t.Error("should contain needle")
	}
	if !strings.Contains(got, "window.setInterval") {
		t.Error("should patch setInterval")
	}
}

func TestScriptletSourcePreventFetch(t *testing.T) {
	got := blocklist.ScriptletSource("prevent-fetch", []string{"analytics"})
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if !strings.Contains(got, "analytics") {
		t.Error("should contain needle")
	}
	if !strings.Contains(got, "window.fetch") {
		t.Error("should patch fetch")
	}
	if !strings.Contains(got, "Promise.resolve") {
		t.Error("should return resolved promise")
	}

	// No args (matches all)
	got = blocklist.ScriptletSource("prevent-fetch", nil)
	if got == "" {
		t.Fatal("should work with no args")
	}
}

func TestScriptletSourceJsonPrune(t *testing.T) {
	got := blocklist.ScriptletSource("json-prune", []string{"ads sponsored"})
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if !strings.Contains(got, "ads sponsored") {
		t.Error("should contain property names")
	}
	if !strings.Contains(got, "JSON.parse") {
		t.Error("should patch JSON.parse")
	}
	// YouTube reads Innertube responses with Response.json(), never JSON.parse.
	if !strings.Contains(got, "Response") {
		t.Error("should patch Response.prototype.json")
	}
}

func TestScriptletSourceJsonPruneNeedle(t *testing.T) {
	// Second argument is a precondition: only prune when all needles are present.
	got := blocklist.ScriptletSource("json-prune", []string{"adPlacements playerAds", "adPlacements"})
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if !strings.Contains(got, `var prunePaths = 'adPlacements playerAds'`) {
		t.Error("first arg should be the prune paths")
	}
	if !strings.Contains(got, `var needlePaths = 'adPlacements'`) {
		t.Error("second arg should be the needle paths")
	}
}

// The real filter text carries one comma, so all the paths land in a single
// argument. TestScriptletSourceJsonPruneNeedle hand-feeds two arguments, a
// shape parseScriptletRule never produces — this one goes through the parser
// so the two can't drift apart again.
func TestScriptletJsonPruneRealFilterLine(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine(`www.youtube.com##+js(json-prune, playerResponse.adPlacements ` +
		`playerResponse.playerAds playerResponse.adSlots adPlacements playerAds adSlots)`)

	rules := rs.ScriptletsForDomain("www.youtube.com")
	if len(rules) != 1 {
		t.Fatalf("got %d scriptlet rules, want 1", len(rules))
	}
	got := blocklist.ScriptletSource(rules[0].Name, rules[0].Args)
	if got == "" {
		t.Fatal("expected non-empty output")
	}

	all := "playerResponse.adPlacements playerResponse.playerAds " +
		"playerResponse.adSlots adPlacements playerAds adSlots"

	if !strings.Contains(got, "var prunePaths = '"+all+"'") {
		t.Errorf("every path should be pruned, got:\n%s", got)
	}
	// uBO's json-prune deletes every needle but only once all of them are
	// found, so the paths double as their own precondition. An empty
	// needle list makes the guard vacuous and the rule prune blindly.
	if !strings.Contains(got, "var needlePaths = '"+all+"'") {
		t.Errorf("paths should also gate the prune, got:\n%s", got)
	}
}

func TestScriptletSourceJsonPruneExplicitNeedlesOverride(t *testing.T) {
	// With an explicit second argument it still wins over the prune paths.
	got := blocklist.ScriptletSource("json-prune", []string{"a.b c.d", "c.d"})
	if !strings.Contains(got, `var needlePaths = 'c.d'`) {
		t.Errorf("explicit needles should be used verbatim, got:\n%s", got)
	}
}

func TestScriptletJsonPruneDomainScoping(t *testing.T) {
	rs := blocklist.NewRuleSet()
	rs.AddLine(`www.youtube.com##+js(json-prune, a.b a.c)`)

	if got := rs.ScriptletsForDomain("www.youtube.com"); len(got) != 1 {
		t.Errorf("www.youtube.com: got %d rules, want 1", len(got))
	}
	// domainMatchesOrIsSubdomain means the apex and m. do not match a
	// www-scoped rule. Worth pinning: it's a silent, easy-to-miss gap.
	if got := rs.ScriptletsForDomain("youtube.com"); len(got) != 0 {
		t.Errorf("youtube.com: got %d rules, want 0", len(got))
	}
	if got := rs.ScriptletsForDomain("m.youtube.com"); len(got) != 0 {
		t.Errorf("m.youtube.com: got %d rules, want 0", len(got))
	}
}

func TestScriptletSourceJsonPruneWildcardTokens(t *testing.T) {
	got := blocklist.ScriptletSource("json-prune", []string{"playlist.[].adserver playlist.*.adserver items[-].ad item*{-}.adserver"})
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	for _, tok := range []string{"[-]", "{-}", "[]"} {
		if !strings.Contains(got, tok) {
			t.Errorf("expected %q token support in output", tok)
		}
	}
}

func TestScriptletSourceRemoveAttr(t *testing.T) {
	// With selector
	got := blocklist.ScriptletSource("remove-attr", []string{"onclick", "div.widget"})
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if !strings.Contains(got, "onclick") {
		t.Error("should contain attribute name")
	}
	if !strings.Contains(got, "div.widget") {
		t.Error("should contain selector")
	}
	if !strings.Contains(got, "MutationObserver") {
		t.Error("should use MutationObserver for continuous removal")
	}

	// Without selector (default to [attr])
	got = blocklist.ScriptletSource("remove-attr", []string{"data-ad"})
	if got == "" {
		t.Fatal("should work with just attribute name")
	}

	if blocklist.ScriptletSource("remove-attr", nil) != "" {
		t.Error("should return empty with no args")
	}
}

// TestScriptletSourceScriptTagSanitization verifies that </script> in
// arguments is escaped to prevent XSS when injected inside a <script> tag.
func TestScriptletSourceScriptTagSanitization(t *testing.T) {
	got := blocklist.ScriptletSource("set-constant", []string{"x</script><img onerror=alert(1)>", "true"})
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if strings.Contains(got, "</script") {
		t.Error("output must not contain literal </script — XSS vulnerability")
	}
	if !strings.Contains(got, `<\/script`) {
		t.Error("</script should be escaped to <\\/script")
	}
}

// TestScriptletSourceIIFEWrapping verifies all scriptlets are wrapped in
// immediately-invoked function expressions to avoid polluting global scope.
func TestScriptletSourceIIFEWrapping(t *testing.T) {
	scriptlets := []struct {
		name string
		args []string
	}{
		{"set-constant", []string{"a", "true"}},
		{"abort-on-property-read", []string{"a"}},
		{"abort-on-property-write", []string{"a"}},
		{"abort-current-inline-script", []string{"a"}},
		{"addEventListener-defuser", nil},
		{"nowebrtc", nil},
		{"no-setTimeout-if", nil},
		{"no-setInterval-if", nil},
		{"prevent-fetch", nil},
		{"json-prune", []string{"a"}},
		{"remove-attr", []string{"a"}},
	}

	for _, tt := range scriptlets {
		t.Run(tt.name, func(t *testing.T) {
			got := blocklist.ScriptletSource(tt.name, tt.args)
			if got == "" {
				t.Fatal("expected non-empty output")
			}
			if !strings.HasPrefix(got, "(function()") {
				t.Errorf("should start with IIFE, got prefix: %q", got[:min(len(got), 30)])
			}
			if !strings.Contains(got, "})();") {
				t.Error("should end with IIFE invocation")
			}
		})
	}
}

// TestScriptletSourceSingleQuoteEscaping verifies that single quotes in
// arguments are escaped properly.
func TestScriptletSourceSingleQuoteEscaping(t *testing.T) {
	got := blocklist.ScriptletSource("abort-on-property-read", []string{"it's.a.test"})
	if got == "" {
		t.Fatal("expected non-empty output")
	}
	if strings.Contains(got, "it's") {
		t.Error("unescaped single quote would break JS string literal")
	}
	if !strings.Contains(got, `it\'s`) {
		t.Error("single quote should be escaped")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
