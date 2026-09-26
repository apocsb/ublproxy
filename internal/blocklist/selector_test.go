package blocklist_test

import (
	"strings"
	"testing"

	"golang.org/x/net/html"

	"ublproxy/internal/blocklist"
)

func parseDoc(t *testing.T, src string) *html.Node {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return doc
}

// collect returns the tag names of all element nodes matching sel.
func collect(doc *html.Node, sel string) []string {
	matcher := blocklist.CompileSelector(sel)
	if matcher == nil {
		return nil
	}
	var out []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && matcher.Matches(n) {
			out = append(out, n.Data+"#"+attrOf(n, "id"))
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return out
}

func attrOf(n *html.Node, name string) string {
	for _, a := range n.Attr {
		if a.Key == name {
			return a.Val
		}
	}
	return ""
}

const selectorDoc = `<html><body>
<div id="a" class="box wide" data-x="foo-bar">
  <p class="text">hello</p>
  <p class="text">second</p>
  <span class="ad">ad</span>
</div>
<div id="b" class="box">
  <a href="/x">link</a>
  <a href="/y">link2</a>
</div>
<section><p id="c" class="text">third</p></section>
</body></html>`

func TestCompileSelectorMatch(t *testing.T) {
	doc := parseDoc(t, selectorDoc)

	tests := []struct {
		sel  string
		want []string
	}{
		{"div", []string{"div#a", "div#b"}},
		{"*", []string{"html#", "head#", "body#", "div#a", "p#", "p#", "span#", "div#b", "a#", "a#", "section#", "p#c"}},
		{"#a", []string{"div#a"}},
		{".box", []string{"div#a", "div#b"}},
		{".box.wide", []string{"div#a"}},
		{".box.missing", nil},
		{"div.box#a", []string{"div#a"}},
		{"p.text", []string{"p#", "p#", "p#c"}},
		{"div p", []string{"p#", "p#"}},
		{"div > p", []string{"p#", "p#"}},
		{"div > span", []string{"span#"}},
		{"section > p", []string{"p#c"}},
		{"div + div", []string{"div#b"}},
		{"span + p", nil},
		{"a ~ a", []string{"a#"}},
		{`[data-x]`, []string{"div#a"}},
		{`[data-x="foo-bar"]`, []string{"div#a"}},
		{`[data-x^="foo"]`, []string{"div#a"}},
		{`[data-x$="bar"]`, []string{"div#a"}},
		{`[data-x*="o-b"]`, []string{"div#a"}},
		{`[data-x="nope"]`, nil},
		{`[class~="wide"]`, []string{"div#a"}},
		{`[class~="wide"] , [class~="box"]`, []string{"div#a", "div#b"}},
		{"p.text, span.ad", []string{"p#", "p#", "span#", "p#c"}},
		{"div:not(.wide)", []string{"div#b"}},
		{"div:has(span)", []string{"div#a"}},
		{"div:has(> span)", []string{"div#a"}},
		{"div:has(+ div)", []string{"div#a"}},
		{"section:has(p)", []string{"section#"}},
		{":root", []string{"html#"}},
		{"p:empty", nil},
		{"div > p:first-child", []string{"p#"}},
		// span is div#a's last child, so neither p is :last-child.
		{"div > p:last-child", nil},
		{"section > p:last-child", []string{"p#c"}},
		{"unknowntag", nil},
		{`a[href^="/x"]`, []string{"a#"}},
	}

	for _, tt := range tests {
		got := collect(doc, tt.sel)
		if strings.Join(got, ",") != strings.Join(tt.want, ",") {
			t.Errorf("selector %q\n got: %v\nwant: %v", tt.sel, got, tt.want)
		}
	}
}

func TestCompileSelectorRelative(t *testing.T) {
	// Relative selectors are only meaningful inside :has(), but they must
	// parse without erroring.
	if blocklist.CompileSelector("> div") == nil {
		t.Error("relative selector should parse")
	}
	if blocklist.CompileSelector("+ div") == nil {
		t.Error("relative selector should parse")
	}
}

func TestCompileSelectorRejects(t *testing.T) {
	for _, sel := range []string{"", "   ", ">", ">>>"} {
		if blocklist.CompileSelector(sel) != nil {
			t.Errorf("selector %q should not compile", sel)
		}
	}
}

// An unevaluable pseudo-class must not match, or rules using it would hide
// far more than they intend.
func TestUnknownPseudoDoesNotMatch(t *testing.T) {
	doc := parseDoc(t, selectorDoc)
	if got := collect(doc, "div:nth-of-type(2)"); len(got) != 0 {
		t.Errorf("expected no matches for unevaluable pseudo, got %v", got)
	}
}

func TestQuotedCommaInSelector(t *testing.T) {
	doc := parseDoc(t, `<html><body><a title="a,b">x</a><a title="c">y</a></body></html>`)
	got := collect(doc, `a[title="a,b"]`)
	if len(got) != 1 {
		t.Errorf("expected 1 match, got %v", got)
	}
}
