package blocklist_test

import (
	"strings"
	"testing"

	"golang.org/x/net/html"

	"ublproxy/internal/blocklist"
)

const procDoc = `<html><body>
<div id="wrap">
  <div class="ad" style="display: block; position: absolute">
    <p>Buy now</p>
    <a href="http://track.example/x" class="promo">Sponsored</a>
  </div>
  <div class="post">
    <p>Real content here</p>
    <a href="/watch">Watch</a>
  </div>
  <div class="ad short">Hi</div>
</div>
<script>var adSlots = 1;</script>
</body></html>`

func applyProc(t *testing.T, rule, src string) string {
	t.Helper()
	pr := blocklist.ParseProceduralRule(rule)
	if pr == nil {
		t.Fatalf("rule %q did not parse", rule)
	}
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pr.ApplyTo(doc, "/watch")
	var b strings.Builder
	if err := html.Render(&b, doc); err != nil {
		t.Fatalf("render: %v", err)
	}
	return b.String()
}

func TestProceduralRemove(t *testing.T) {
	out := applyProc(t, `example.com#?#.ad:remove()`, procDoc)
	if strings.Contains(out, `class="ad"`) {
		t.Error("ad div should be removed")
	}
	if !strings.Contains(out, `class="post"`) {
		t.Error("post div should survive")
	}
	if strings.Contains(out, `class="ad short"`) {
		t.Error("second ad div should be removed too")
	}
}

func TestProceduralRemoveAttr(t *testing.T) {
	out := applyProc(t, `example.com#?#a:remove-attr(href)`, procDoc)
	if strings.Contains(out, "track.example") {
		t.Error("href should be removed")
	}
	if strings.Contains(out, `href="/watch"`) {
		t.Error("unrelated href should survive")
	}
}

func TestProceduralRemoveClass(t *testing.T) {
	out := applyProc(t, `example.com#?#.post:remove-class(post)`, procDoc)
	if strings.Contains(out, `class="post"`) {
		t.Error("class should be removed")
	}
	if !strings.Contains(out, "Real content here") {
		t.Error("node itself should survive")
	}
}

func TestProceduralStyle(t *testing.T) {
	out := applyProc(t, `example.com#?#.ad:style(display: none !important)`, procDoc)
	if !strings.Contains(out, "display: none !important") {
		t.Errorf("style not applied, got: %s", out)
	}
}

func TestProceduralHasText(t *testing.T) {
	out := applyProc(t, `example.com#?#p:has-text(Buy):remove()`, procDoc)
	if strings.Contains(out, "Buy now") {
		t.Error("paragraph with the text should be removed")
	}
	if !strings.Contains(out, "Real content here") {
		t.Error("other paragraph should survive")
	}
}

func TestProceduralMinTextLength(t *testing.T) {
	out := applyProc(t, `example.com#?#.ad:has-text(Sponsored):remove()`, procDoc)
	if strings.Contains(out, "Sponsored") {
		t.Error("ad containing the text should be removed")
	}
	if !strings.Contains(out, `class="ad short"`) {
		t.Error("ad without the text should survive")
	}
}

func TestProceduralUpward(t *testing.T) {
	// The anchor is the target, but :upward(2) resolves to the wrapper div.
	out := applyProc(t, `example.com#?#a.promo:upward(2):remove()`, procDoc)
	if strings.Contains(out, `id="wrap"`) {
		t.Error("ancestor two levels up should be removed")
	}
	// The script is a sibling of the wrapper, not a descendant, so it stays.
	if !strings.Contains(out, "var adSlots") {
		t.Error("sibling script should survive")
	}
}

func TestProceduralUpwardSelector(t *testing.T) {
	out := applyProc(t, `example.com#?#a[href^="http"]:upward(.post):remove()`, procDoc)
	// The tracking anchor is inside .ad, not .post, so nothing is removed.
	if !strings.Contains(out, `class="post"`) {
		t.Error("nothing should have matched")
	}
}

func TestProceduralMatchesAttr(t *testing.T) {
	out := applyProc(t, `example.com#?#div:matches-attr(class, /^ad/):remove()`, procDoc)
	if strings.Contains(out, `class="ad`) {
		t.Error("ad divs should be removed")
	}
	if !strings.Contains(out, `class="post"`) {
		t.Error("post should survive")
	}
}

func TestProceduralMatchesCSS(t *testing.T) {
	out := applyProc(t, `example.com#?#div:matches-css(position, absolute):remove()`, procDoc)
	if strings.Contains(out, `class="ad"`) {
		t.Error("absolutely positioned ad should be removed")
	}
	if !strings.Contains(out, `class="ad short"`) {
		t.Error("the other ad should survive")
	}
}

func TestProceduralMatchesPath(t *testing.T) {
	out := applyProc(t, `example.com#?#.post:matches-path(/^\/watch/):remove-class(post)`, procDoc)
	if strings.Contains(out, `class="post"`) {
		t.Errorf("path matched so the class should be gone, got: %s", out)
	}
	if !strings.Contains(out, `class="ad"`) {
		t.Error("other rules should be untouched")
	}
}

func TestProceduralMatchesPathNoMatch(t *testing.T) {
	out := applyProc(t, `example.com#?#.post:matches-path(/^\/other/):remove-class(post)`, procDoc)
	if !strings.Contains(out, `class="post"`) {
		t.Error("path did not match, nothing should change")
	}
}

func TestProceduralNot(t *testing.T) {
	out := applyProc(t, `example.com#?#div:not(:has-text(Buy)):remove()`, procDoc)
	if !strings.Contains(out, `class="ad"`) {
		t.Error("ad div contains the text so :not fails, it should survive")
	}
	if strings.Contains(out, `class="post"`) {
		t.Error("post div should be removed")
	}
}

func TestProceduralOthers(t *testing.T) {
	out := applyProc(t, `example.com#?#a:others(.promo):remove()`, procDoc)
	if strings.Contains(out, `class="promo"`) {
		t.Error("the only .promo anchor should be removed")
	}
	if !strings.Contains(out, `href="/watch"`) {
		t.Error("other anchors should survive")
	}
}

func TestProceduralHTMLFilter(t *testing.T) {
	out := applyProc(t, `example.com##^script:has-text(adSlots)`, procDoc)
	if strings.Contains(out, "var adSlots") {
		t.Error("inline script should be removed")
	}
	if !strings.Contains(out, `class="post"`) {
		t.Error("rest of the document should survive")
	}
}

func TestProceduralDomainScoping(t *testing.T) {
	pr := blocklist.ParseProceduralRule(`other.com#?#.ad:remove()`)
	if pr == nil {
		t.Fatal("rule should parse")
	}
	if pr.AppliesTo("example.com") {
		t.Error("rule scoped to other.com should not apply to example.com")
	}
	if !pr.AppliesTo("www.other.com") {
		t.Error("rule should apply to a subdomain of other.com")
	}
}

func TestProceduralException(t *testing.T) {
	pr := blocklist.ParseProceduralRule(`example.com#@?#.ad:remove()`)
	if pr == nil {
		t.Fatal("exception rule should parse")
	}
	if !pr.Exception {
		t.Error("should be marked as an exception")
	}
}

// A rule using an operator we don't implement must not silently act on the
// whole document.
func TestProceduralUnsupportedOperatorIsRejected(t *testing.T) {
	for _, rule := range []string{
		`example.com#?#div:watch-attr(class)`,
		`example.com#?#div:matches-css-before(color, red)`,
	} {
		if blocklist.ParseProceduralRule(rule) != nil {
			t.Errorf("rule %q should not parse into something we would act on", rule)
		}
	}
}

func TestProceduralGarbageIsRejected(t *testing.T) {
	for _, rule := range []string{
		`example.com#?#`,
		`example.com#?#div:bogus-op()`,
		`example.com#?#div:has-text(`,
	} {
		if pr := blocklist.ParseProceduralRule(rule); pr != nil {
			t.Errorf("rule %q should be rejected, got %+v", rule, pr)
		}
	}
}

// A base selector may legitimately contain colons of its own.
func TestProceduralBaseSelectorKeepsCSSColons(t *testing.T) {
	pr := blocklist.ParseProceduralRule(`example.com#?#div:has(p):has-text(Buy):remove()`)
	if pr == nil {
		t.Fatal("rule should parse")
	}
	if pr.BaseSelector != "div:has(p)" {
		t.Errorf("base selector = %q, want %q", pr.BaseSelector, "div:has(p)")
	}
	if got := pr.OpNames(); len(got) != 1 || got[0] != "has-text" {
		t.Errorf("ops = %v, want [has-text]", got)
	}
	if pr.ActionName() != "remove" {
		t.Errorf("action = %q, want remove", pr.ActionName())
	}
}

func TestProceduralNoActionMarksNodes(t *testing.T) {
	doc, _ := html.Parse(strings.NewReader(procDoc))
	pr := blocklist.ParseProceduralRule(`example.com#?#.ad:has-text(Buy)`)
	if pr == nil {
		t.Fatal("rule should parse")
	}
	if pr.HasAction {
		t.Fatal("rule should have no action")
	}
	if n := pr.ApplyTo(doc, "/watch"); n != 1 {
		t.Errorf("matched %d nodes, want 1", n)
	}
	matched := pr.Matched()
	if len(matched) != 1 {
		t.Fatalf("Matched() returned %d nodes, want 1", len(matched))
	}
	if got := attrOf(matched[0], "class"); got != "ad" {
		t.Errorf("matched node class = %q, want %q", got, "ad")
	}
}
