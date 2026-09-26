package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	htmlpkg "html"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/html"

	"ublproxy/internal/blocklist"
)

// statsHeaderName is the response header the proxy adds to every proxied
// response, reporting how many filtering operations were applied.
const statsHeaderName = "X-Ublproxy-Stats"

// elementHidingStats reports what the proxy did to an HTML response.
type elementHidingStats struct {
	Modified   bool // true if the response body was changed
	Hidden     int  // CSS element-hiding selectors injected
	Stripped   int  // HTML elements (script/iframe/object/embed) removed
	Procedural int  // nodes changed by #?# / ##^ procedural rules
}

// header returns the stats formatted for the X-Ublproxy-Stats response header.
func (s elementHidingStats) header() string {
	return fmt.Sprintf("hidden=%d; stripped=%d; procedural=%d", s.Hidden, s.Stripped, s.Procedural)
}

// styleCloseRe matches </style in any case — used to prevent XSS via
// user-created CSS rules that contain a closing </style> tag.
var styleCloseRe = regexp.MustCompile(`(?i)</style`)

// voidElements are HTML elements that have no closing tag.
var voidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true,
	"embed": true, "hr": true, "img": true, "input": true,
	"link": true, "meta": true, "param": true, "source": true,
	"track": true, "wbr": true,
}

// srcBlockableTags maps element names to the attribute that carries their
// external resource URL. If the resolved URL is blocked, the element is stripped.
var srcBlockableTags = map[string]string{
	"script": "src",
	"iframe": "src",
	"object": "data",
	"embed":  "src",
}

// srcBlockContext carries the page context needed to resolve relative src
// attributes and check them against URL blocking rules. Uses the proxy's
// layered shouldBlock for per-user rule evaluation.
type srcBlockContext struct {
	scheme   string
	host     string
	proxy    *proxyHandler
	clientIP string
}

// resolveSrc resolves an element's src attribute to an absolute URL.
// Protocol-relative (//host/path), absolute (/path), and fully qualified
// URLs are all handled.
func (sc srcBlockContext) resolveSrc(src string) string {
	if strings.HasPrefix(src, "//") {
		return sc.scheme + ":" + src
	}
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		return src
	}
	if strings.HasPrefix(src, "/") {
		return sc.scheme + "://" + sc.host + src
	}
	return sc.scheme + "://" + sc.host + "/" + src
}

// applyElementHiding checks if the response is HTML and applies CSS-based
// element hiding, src-based resource stripping, and bootstrap script injection.
// Elements that load external resources (script, iframe, object, embed) whose
// URL resolves to a blocked address are stripped from the DOM. All other element
// hiding selectors are applied via CSS display:none injection only — content
// elements are never removed from the DOM to avoid stripping legitimate page
// content that happens to match generic selectors.
// The bootstrap script for the element picker is injected when a session
// exists for the client IP, unless insecure is true (plain HTTP proxy
// connection) — the token must not be sent over unencrypted connections.
// Returns the modified body and true, or nil and false if unmodified.
// Handles gzip, brotli, and zstd compressed responses transparently.
func (p *proxyHandler) applyElementHiding(resp *http.Response, host, clientIP string, insecure bool) ([]byte, elementHidingStats) {
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text/html") {
		return nil, elementHidingStats{}
	}

	baseline := p.getBaselineRules()
	credID := p.credentialForIP(clientIP)
	userRS := p.getUserRules(credID)

	// Merge element hiding from baseline and user rules
	var baselineEH, userEH *blocklist.ElementHiding
	if baseline != nil {
		baselineEH = baseline.ElementHidingForDomain(host)
	}
	if userRS != nil {
		userEH = userRS.ElementHidingForDomain(host)
	}

	hasURLRules := (baseline != nil && (baseline.HostCount() > 0 || baseline.RuleCount() > 0)) ||
		(userRS != nil && (userRS.HostCount() > 0 || userRS.RuleCount() > 0))

	// Collect scriptlet rules for this domain from both rulesets
	scriptletTag := buildScriptletTag(
		baseline.ScriptletsForDomain(host),
		userRS.ScriptletsForDomain(host),
	)

	// Generate bootstrap script tag (empty string if no session).
	// Skip on insecure (plain HTTP) connections to avoid leaking the
	// session token over unencrypted traffic.
	var scriptTag string
	if !insecure {
		scriptTag = p.bootstrapScriptTag(clientIP, host)
	}

	// Nothing to do if there are no rules AND no script to inject
	hasProcedural := baseline.HasProcedural() || userRS.HasProcedural()
	if baselineEH == nil && userEH == nil && !hasURLRules && scriptTag == "" &&
		scriptletTag == "" && !hasProcedural {
		return nil, elementHidingStats{}
	}

	var body []byte
	var err error
	encoding := resp.Header.Get("Content-Encoding")
	switch {
	case strings.Contains(encoding, "gzip"):
		gr, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			slog.Warn("elemhide/skip", "reason", "gzip init failed", "host", host, "err", gzErr)
			return nil, elementHidingStats{}
		}
		body, err = io.ReadAll(gr)
		gr.Close()
	case strings.Contains(encoding, "br"):
		body, err = io.ReadAll(brotli.NewReader(resp.Body))
	case strings.Contains(encoding, "zstd"):
		var zr *zstd.Decoder
		zr, err = zstd.NewReader(resp.Body)
		if err != nil {
			slog.Warn("elemhide/skip", "reason", "zstd init failed", "host", host, "err", err)
			return nil, elementHidingStats{}
		}
		body, err = io.ReadAll(zr)
		zr.Close()
	case encoding == "":
		body, err = io.ReadAll(resp.Body)
	default:
		slog.Warn("elemhide/skip", "reason", "unsupported encoding", "encoding", encoding, "host", host)
		return nil, elementHidingStats{}
	}
	if err != nil {
		slog.Warn("elemhide/skip", "reason", "decompression failed", "encoding", encoding, "host", host, "err", err)
		return nil, elementHidingStats{}
	}

	var stats elementHidingStats
	stats.Modified = true

	// For src-based resource stripping, use the layered shouldBlock
	// approach via a proxy-aware srcBlockContext.
	sc := srcBlockContext{scheme: "https", host: host, proxy: p, clientIP: clientIP}
	modified, strippedCount := stripBlockedResources(body, sc)
	stats.Stripped = strippedCount

	// Check cosmetic filter exceptions ($elemhide, $generichide, $specifichide)
	pageURL := "https://" + host + "/"
	cosmeticExc := baseline.CosmeticFilterExceptions(pageURL) |
		userRS.CosmeticFilterExceptions(pageURL)

	// Merge baseline + user element hiding selectors, then filter to only
	// those that match classes/IDs actually present in the HTML. This avoids
	// injecting tens of thousands of global selectors that don't apply.
	// Domain-scoped selectors skip the pre-filter: on single-page apps like
	// YouTube the interesting elements are built by JavaScript and never
	// appear in the server's HTML, so the filter would drop rules that do
	// match once the page is live.
	generic, specific := mergeElementHidingSelectors(baselineEH, userEH, userRS, host, cosmeticExc)
	selectors := append(filterSelectors(generic, modified), specific...)
	css := buildElementHidingCSS(dedupeSelectors(selectors))

	// Procedural DOM filters (#?#, ##^) rewrite the tree. They run before the
	// token pre-filter so their matches count. The parse/render round trip is
	// only worth its cost when a rule actually applies to this host, so gate it
	// on there being any.
	var markerCSS string
	if hasProcedural {
		modified, markerCSS, stats.Procedural = applyProceduralDOM(modified, baseline, userRS, host, resp)
		if markerCSS != "" {
			css += markerCSS
		}
	}

	if css != "" {
		safeCSS := styleCloseRe.ReplaceAllString(css, `<\/style`)
		styleTag := []byte("<style>" + safeCSS + "</style>")
		modified = injectStyleTag(modified, styleTag)
		stats.Hidden = len(selectors)
		rule := truncateRule(strings.Join(selectors, ", "), 80)
		p.logActivity(ActivityElementHidden, host, "", rule, clientIP, credID)
		logElementHidden(host, rule, clientIP, credID)
	}

	// Inject scriptlets at document start so they win the race against the
	// page's own inline scripts.
	if scriptletTag != "" {
		modified = injectAtDocumentStart(modified, []byte(withCSPNonce(scriptletTag, cspNonce(modified))))
	}

	// Inject the bootstrap script for the element picker
	if scriptTag != "" {
		modified = injectBeforeClose(modified, []byte(scriptTag), []byte("</body>"), []byte("</html>"))
	}

	// Remove Content-Encoding since we send uncompressed to the client.
	// The proxy-to-client hop is typically localhost so this is fine.
	resp.Header.Del("Content-Encoding")

	return modified, stats
}

// proceduralHideClass marks nodes that a no-action procedural rule selected,
// so the same hiding the rule asks for is emitted as CSS instead of a node
// edit. CSS over removal because a removal changes the tree the page's own
// scripts hydrate against.
const proceduralHideClass = "ublp-phid"

// applyProceduralDOM runs procedural rules against the response body. It
// returns the (possibly unchanged) body, any marker CSS to inject, and the
// number of nodes the rules affected.
//
// A nil or non-HTML body is returned untouched: rules that don't apply to this
// host must not cost a parse/render round trip.
func applyProceduralDOM(body []byte, baseline, userRS *blocklist.RuleSet, host string, resp *http.Response) ([]byte, string, int) {
	baseRules, baseExc := baseline.ProceduralForDomain(host)
	userRules, userExc := userRS.ProceduralForDomain(host)
	if len(baseRules) == 0 && len(userRules) == 0 &&
		len(baseExc) == 0 && len(userExc) == 0 {
		return body, "", 0
	}

	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		// Truncated or malformed markup: the token CSS path still works.
		slog.Warn("procedural/skip", "reason", "parse failed", "host", host, "err", err)
		return body, "", 0
	}

	pagePath := "/"
	if resp.Request != nil && resp.Request.URL != nil {
		pagePath = resp.Request.URL.Path
	}

	// Exceptions first: a #@?# run marks nodes so the matching #?# skips them.
	// Rules without an action only mark, for the caller to hide with CSS.
	seen := make(map[*html.Node]bool)
	var marked []*html.Node
	mark := func(nodes []*html.Node) {
		for _, n := range nodes {
			if !seen[n] {
				seen[n] = true
				marked = append(marked, n)
			}
		}
	}

	count := 0
	for _, exc := range baseExc {
		if exc.Excepts(baseRules) {
			count += exc.ApplyTo(doc, pagePath)
		}
	}
	for _, exc := range userExc {
		if exc.Excepts(baseRules) || exc.Excepts(userRules) {
			count += exc.ApplyTo(doc, pagePath)
		}
	}
	for _, rule := range baseRules {
		if n := rule.ApplyTo(doc, pagePath); n > 0 {
			count += n
			if !rule.HasAction {
				mark(rule.Matched())
			}
		}
	}
	for _, rule := range userRules {
		if n := rule.ApplyTo(doc, pagePath); n > 0 {
			count += n
			if !rule.HasAction {
				mark(rule.Matched())
			}
		}
	}

	if count == 0 {
		// Nothing matched, so leave the original bytes alone rather than
		// shipping a normalized round trip.
		return body, "", 0
	}

	for _, n := range marked {
		addClass(n, proceduralHideClass)
	}

	var buf bytes.Buffer
	if err := html.Render(&buf, doc); err != nil {
		slog.Warn("procedural/skip", "reason", "render failed", "host", host, "err", err)
		return body, "", 0
	}

	marker := ""
	if len(marked) > 0 {
		marker = "." + proceduralHideClass + " {\n  display: none !important;\n}\n"
	}
	return buf.Bytes(), marker, count
}

func addClass(n *html.Node, class string) {
	for _, a := range n.Attr {
		if a.Key == "class" {
			for _, f := range strings.Fields(a.Val) {
				if f == class {
					return
				}
			}
			a.Val = a.Val + " " + class
			return
		}
	}
	n.Attr = append(n.Attr, html.Attribute{Key: "class", Val: class})
}

// mergeElementHidingSelectors collects element hiding selectors from baseline
// and user RuleSets for a specific domain. User #@# exception rules suppress
// matching baseline ## selectors. Cosmetic exceptions ($elemhide, $generichide,
// $specifichide) are applied to suppress categories of selectors.
// Generic and domain-specific selectors are returned separately because only
// the generic ones are safe to pre-filter against the server's HTML.
// Returns nil slices if no selectors apply.
func mergeElementHidingSelectors(baseline, user *blocklist.ElementHiding, userRS *blocklist.RuleSet, domain string, cosmeticExc blocklist.CosmeticFilter) (generic, specific []string) {
	// $elemhide disables all element hiding
	if cosmeticExc&blocklist.CosmeticElemHide != 0 {
		return nil, nil
	}

	// Add baseline selectors, filtering out any excepted by user #@# rules
	// or cosmetic exception options
	if baseline != nil {
		if cosmeticExc&blocklist.CosmeticGenericHide == 0 {
			for _, sel := range baseline.GenericSelectors {
				if userRS != nil && userRS.IsElementHideExcepted(sel, domain) {
					continue
				}
				generic = append(generic, sel)
			}
		}
		if cosmeticExc&blocklist.CosmeticSpecificHide == 0 {
			for _, sel := range baseline.SpecificSelectors {
				if userRS != nil && userRS.IsElementHideExcepted(sel, domain) {
					continue
				}
				specific = append(specific, sel)
			}
		}
	}

	// Add user selectors (their own internal exceptions already applied)
	if user != nil {
		if cosmeticExc&blocklist.CosmeticGenericHide == 0 {
			generic = append(generic, user.GenericSelectors...)
		}
		if cosmeticExc&blocklist.CosmeticSpecificHide == 0 {
			specific = append(specific, user.SpecificSelectors...)
		}
	}

	return generic, specific
}

// dedupeSelectors drops repeated selectors. A rule can be present in both the
// baseline and a subscription, and injecting it twice is pure bytes on the
// wire. Order is preserved so the first occurrence wins.
func dedupeSelectors(selectors []string) []string {
	seen := make(map[string]bool, len(selectors))
	out := selectors[:0]
	for _, sel := range selectors {
		if seen[sel] {
			continue
		}
		seen[sel] = true
		out = append(out, sel)
	}
	return out
}

// maxSelectorsPerRule limits the number of selectors in a single CSS rule.
// Chrome truncates rules that exceed its internal selector limit (~4096),
// silently breaking element hiding. Chunking into multiple rules avoids this.
const maxSelectorsPerRule = 4096

// buildElementHidingCSS produces a display:none stylesheet from a list of
// CSS selectors. Rules are chunked to stay within browser selector limits.
// Returns empty string if the list is empty.
func buildElementHidingCSS(selectors []string) string {
	if len(selectors) == 0 {
		return ""
	}
	if len(selectors) <= maxSelectorsPerRule {
		return strings.Join(selectors, ",\n") + " {\n  display: none !important;\n}\n"
	}
	var b strings.Builder
	for i := 0; i < len(selectors); i += maxSelectorsPerRule {
		end := i + maxSelectorsPerRule
		if end > len(selectors) {
			end = len(selectors)
		}
		b.WriteString(strings.Join(selectors[i:end], ",\n"))
		b.WriteString(" {\n  display: none !important;\n}\n")
	}
	return b.String()
}

// buildScriptletTag generates a <script> tag containing all applicable
// scriptlets for the current page, merged from baseline and user rulesets.
// Each scriptlet is resolved to JavaScript via ScriptletSource and wrapped
// in a single <script> tag. Returns empty string if no scriptlets apply.
func buildScriptletTag(baselineScriptlets, userScriptlets []*blocklist.ScriptletRule) string {
	if len(baselineScriptlets) == 0 && len(userScriptlets) == 0 {
		return ""
	}

	var b strings.Builder
	wrote := false

	for _, s := range baselineScriptlets {
		js := blocklist.ScriptletSource(s.Name, s.Args)
		if js != "" {
			b.WriteString(js)
			wrote = true
		}
	}
	for _, s := range userScriptlets {
		js := blocklist.ScriptletSource(s.Name, s.Args)
		if js != "" {
			b.WriteString(js)
			wrote = true
		}
	}

	if !wrote {
		return ""
	}

	return "<script>" + b.String() + "</script>"
}

// cspNonce returns the first nonce attribute value present in the page, or "".
// A response whose CSP lists a nonce ignores 'unsafe-inline', so an injected
// inline script carrying no nonce is refused outright and the scriptlet is a
// silent no-op. YouTube publishes one, which made every ##+js() rule dead
// there until this was noticed. We reuse the page's own nonce because we are
// rewriting that very response, so the value is already valid for it.
func cspNonce(htmlDoc []byte) string {
	const key = `nonce="`
	i := indexCaseInsensitive(htmlDoc, []byte(key))
	if i < 0 {
		return ""
	}
	rest := htmlDoc[i+len(key):]
	j := bytes.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return string(rest[:j])
}

// withCSPNonce adds a nonce attribute to a generated <script> tag. A no-op when
// the page has no nonce, which is the common case and always safe.
func withCSPNonce(tag, nonce string) string {
	if nonce == "" {
		return tag
	}
	return strings.Replace(tag, "<script>", `<script nonce="`+nonce+`">`, 1)
}

// injectBeforeClose inserts content before the first found closing tag,
// or appends if none is found. Tags are tried in order.
func injectBeforeClose(htmlDoc, content []byte, tags ...[]byte) []byte {
	for _, tag := range tags {
		if idx := indexCaseInsensitive(htmlDoc, tag); idx >= 0 {
			return insertAt(htmlDoc, content, idx)
		}
	}
	return append(htmlDoc, content...)
}

// stripBlockedResources uses the HTML tokenizer to walk through the HTML and
// strip elements (script, iframe, object, embed) whose external resource URL
// resolves to a blocked address. Other elements are passed through unchanged —
// element hiding for those is handled by CSS injection only.
func stripBlockedResources(src []byte, sc srcBlockContext) ([]byte, int) {
	if sc.proxy == nil {
		return src, 0
	}

	var buf bytes.Buffer
	buf.Grow(len(src))

	tokenizer := html.NewTokenizer(bytes.NewReader(src))
	stripped := 0

	for {
		tt := tokenizer.Next()

		switch tt {
		case html.ErrorToken:
			if tokenizer.Err() == io.EOF {
				return buf.Bytes(), stripped
			}
			buf.Write(tokenizer.Raw())
			return buf.Bytes(), stripped

		case html.StartTagToken:
			tn, hasAttr := tokenizer.TagName()
			tagNameLower := strings.ToLower(string(tn))

			// Save raw bytes before consuming attributes. TagAttr()
			// causes Raw() to return reconstructed HTML with lowercased
			// attribute names, which breaks React hydration.
			rawBytes := copyBytes(tokenizer.Raw())

			urlAttr, blockable := srcBlockableTags[tagNameLower]
			if !blockable || !hasAttr {
				buf.Write(rawBytes)
				continue
			}

			attrs := collectAttrs(tokenizer, hasAttr)
			urlVal, ok := attrs[urlAttr]
			if !ok || urlVal == "" {
				buf.Write(rawBytes)
				continue
			}

			resolved := sc.resolveSrc(urlVal)
			ctx := blocklist.MatchContext{PageDomain: sc.host}
			if !sc.proxy.shouldBlock(sc.clientIP, resolved, ctx) {
				buf.Write(rawBytes)
				continue
			}

			// HTML-encode the URL to prevent breaking out of the comment
			replacement := "<!-- ublproxy: blocked " + tagNameLower + " " + htmlpkg.EscapeString(urlVal) + " -->"
			buf.WriteString(replacement)
			stripped++
			if !voidElements[tagNameLower] {
				skipUntilClose(tokenizer, tagNameLower)
			}

		default:
			buf.Write(tokenizer.Raw())
		}
	}
}

// copyBytes returns a copy of b. The tokenizer's Raw() returns a slice into
// an internal buffer that is overwritten on the next call, so we must copy.
func copyBytes(b []byte) []byte {
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}

// collectAttrs reads all attributes from the tokenizer for the current tag.
func collectAttrs(tokenizer *html.Tokenizer, hasAttr bool) map[string]string {
	attrs := make(map[string]string)
	if !hasAttr {
		return attrs
	}
	for {
		key, val, more := tokenizer.TagAttr()
		attrs[strings.ToLower(string(key))] = string(val)
		if !more {
			break
		}
	}
	return attrs
}

// skipUntilClose consumes tokens until the matching end tag for the given
// tag name is found, tracking nesting depth for same-name tags.
func skipUntilClose(tokenizer *html.Tokenizer, tagName string) {
	depth := 1
	for depth > 0 {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return
		case html.StartTagToken:
			tn, _ := tokenizer.TagName()
			if strings.ToLower(string(tn)) == tagName {
				depth++
			}
		case html.EndTagToken:
			tn, _ := tokenizer.TagName()
			if strings.ToLower(string(tn)) == tagName {
				depth--
			}
		}
	}
}

// injectAtDocumentStart inserts content as the first child of <head>, so it
// runs before any script the page itself puts there. Falls back through
// <html>, </head> and </body> for documents without a head, and appends if
// none of those exist.
func injectAtDocumentStart(htmlDoc, content []byte) []byte {
	for _, tag := range []string{"<head", "<html"} {
		if end := endOfOpenTag(htmlDoc, tag); end >= 0 {
			return insertAt(htmlDoc, content, end)
		}
	}
	return injectBeforeClose(htmlDoc, content, []byte("</head>"), []byte("</body>"), []byte("</html>"))
}

// endOfOpenTag returns the offset just past the '>' closing the given start
// tag, or -1 if the tag isn't present. Quoted attribute values are skipped so
// a '>' inside an attribute doesn't end the tag early.
func endOfOpenTag(htmlDoc []byte, tag string) int {
	search := 0
	for {
		idx := indexCaseInsensitiveFrom(htmlDoc, []byte(tag), search)
		if idx < 0 {
			return -1
		}
		// Require a tag boundary so "<header>" doesn't match "<head".
		after := idx + len(tag)
		if after < len(htmlDoc) {
			c := htmlDoc[after]
			if c != '>' && c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '/' {
				search = after
				continue
			}
		}
		var quote byte
		for i := after; i < len(htmlDoc); i++ {
			c := htmlDoc[i]
			switch {
			case quote != 0:
				if c == quote {
					quote = 0
				}
			case c == '"' || c == '\'':
				quote = c
			case c == '>':
				return i + 1
			}
		}
		return -1
	}
}

// injectStyleTag inserts the style tag as early as possible in the document.
func injectStyleTag(htmlDoc, styleTag []byte) []byte {
	return injectAtDocumentStart(htmlDoc, styleTag)
}

func insertAt(original, insert []byte, pos int) []byte {
	result := make([]byte, len(original)+len(insert))
	copy(result, original[:pos])
	copy(result[pos:], insert)
	copy(result[pos+len(insert):], original[pos:])
	return result
}

// indexCaseInsensitive finds needle in haystack without allocating a
// full lowercase copy. needle must already be lowercase.
func indexCaseInsensitive(haystack, needle []byte) int {
	return indexCaseInsensitiveFrom(haystack, needle, 0)
}

// indexCaseInsensitiveFrom is indexCaseInsensitive starting at from.
func indexCaseInsensitiveFrom(haystack, needle []byte, from int) int {
	if from < 0 {
		from = 0
	}
	if len(needle) > len(haystack)-from {
		return -1
	}
	for i := from; i <= len(haystack)-len(needle); i++ {
		if bytes.EqualFold(haystack[i:i+len(needle)], needle) {
			return i
		}
	}
	return -1
}
