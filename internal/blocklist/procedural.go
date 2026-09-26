package blocklist

import (
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"
)

// Procedural cosmetic filters (#?# and ##^) are evaluated against a parsed
// copy of the response document. The browser-facing `##` path never needs
// this: it hands selectors to the browser as CSS. Procedural filters are the
// ones the proxy has to answer for itself.
//
// The hard limit: this only sees the document the server sent. Anything built
// by JavaScript afterwards is out of reach, which is why :watch-attr() and
// :matches-css-before() are not implemented rather than approximated.

type procOp struct {
	name string
	args string
	// inner holds the compiled selector for operators that take one.
	inner *selMatcher
	// innerOps holds the chain nested inside :not(...).
	innerOps []procOp
	re       *regexp.Regexp
	num      int
	// neg is set for the "-name" negated spellings uBlock accepts.
	neg bool
}

// ProceduralRule is a parsed #?# or ##^ filter.
type ProceduralRule struct {
	BaseSelector string
	Ops          []procOp
	// Action is the trailing operator, if the rule has one. Only one action
	// per rule is meaningful.
	Action     procOp
	HasAction  bool
	HTMLFilter bool // ##^ form: match raw HTML, always an action
	Exception  bool

	// matched holds the nodes selected by a rule with no action operator.
	// They get hidden through a generated marker class.
	matched []*html.Node

	IncludeDomains []string
	ExcludeDomains []string
}

// proceduralOps lists the operators this engine understands. Used both to
// split the selector and to report what a rule needs that we can't do.
var proceduralOps = map[string]bool{
	"has-text":        true,
	"min-text-length": true,
	"matches-attr":    true,
	"matches-css":     true,
	"matches-path":    true,
	"upward":          true,
	"others":          true,
	"xpath":           true,
	"not":             true,
	"remove":          true,
	"remove-attr":     true,
	"remove-class":    true,
	"style":           true,
}

// unsupportedOps are uBlock operators we deliberately don't implement. Kept
// here so validation can say "not supported" rather than "malformed".
var unsupportedOps = map[string]bool{
	"watch-attr":         true,
	"matches-css-before": true,
	"matches-css-after":  true,
	"matches-media":      true,
}

// isProceduralLine reports whether a line uses the #?# or ##^ separator.
func isProceduralLine(line string) bool {
	return strings.Contains(line, "#?#") || strings.Contains(line, "##^")
}

// ParseProceduralRule parses a #?# or ##^ line. Returns nil if the line isn't
// procedural or uses something this engine won't act on.
func ParseProceduralRule(line string) *ProceduralRule { return parseProceduralRule(line) }

// ApplyTo evaluates the rule against a parsed document, mutating it. Returns
// the number of nodes affected.
func (r *ProceduralRule) ApplyTo(doc *html.Node, pagePath string) int {
	return r.applyTo(doc, pagePath)
}

// AppliesTo reports whether the rule's domain scoping includes domain.
func (r *ProceduralRule) AppliesTo(domain string) bool { return r.appliesTo(domain) }

// Matched returns the nodes a rule with no action operator selected.
func (r *ProceduralRule) Matched() []*html.Node { return r.matched }

// Base returns the CSS part of the rule, before any procedural operators.
func (r *ProceduralRule) Base() string { return r.BaseSelector }

// IsHTMLFilter reports whether the rule used the ##^ form.
func (r *ProceduralRule) IsHTMLFilter() bool { return r.HTMLFilter }

// OpNames returns the filter operator names in the chain, in order.
func (r *ProceduralRule) OpNames() []string {
	out := make([]string, 0, len(r.Ops))
	for _, op := range r.Ops {
		out = append(out, op.name)
	}
	return out
}

// ActionName returns the trailing action operator's name, or "" if none.
func (r *ProceduralRule) ActionName() string {
	if !r.HasAction {
		return ""
	}
	return r.Action.name
}

// parseProceduralRule parses a #?# or ##^ line. Returns nil if the line isn't
// procedural or can't be understood.
func parseProceduralRule(line string) *ProceduralRule {
	var rule *ProceduralRule

	switch {
	case strings.Contains(line, "#@?#"):
		rule = &ProceduralRule{Exception: true}
	case strings.Contains(line, "##^"):
		rule = &ProceduralRule{HTMLFilter: true}
	case strings.Contains(line, "#?#"):
		rule = &ProceduralRule{}
	default:
		return nil
	}

	// Exceptions use #@?#
	domainPart := ""
	rest := ""
	if i := strings.Index(line, "#@?#"); i >= 0 {
		rule.Exception = true
		domainPart, rest = line[:i], line[i+4:]
	} else if rule.HTMLFilter {
		i := strings.Index(line, "##^")
		domainPart, rest = line[:i], line[i+3:]
	} else {
		i := strings.Index(line, "#?#")
		domainPart, rest = line[:i], line[i+3:]
	}

	for _, d := range strings.Split(domainPart, ",") {
		d = strings.TrimSpace(strings.ToLower(d))
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "~") {
			rule.ExcludeDomains = append(rule.ExcludeDomains, d[1:])
		} else {
			rule.IncludeDomains = append(rule.IncludeDomains, d)
		}
	}

	base, ops := splitOperators(rest)
	rule.BaseSelector = strings.TrimSpace(base)
	if rule.BaseSelector == "" && !rule.HTMLFilter {
		return nil
	}
	if rule.BaseSelector == "" {
		// ##^ with no selector means "every element", used with :has-text
		// style predicates.
		rule.BaseSelector = "*"
	}

	for _, op := range ops {
		parsed, ok := parseProcOp(op)
		if !ok {
			return nil
		}
		if parsed.name == "remove" || parsed.name == "remove-attr" ||
			parsed.name == "remove-class" || parsed.name == "style" {
			rule.Action = parsed
			rule.HasAction = true
			continue
		}
		rule.Ops = append(rule.Ops, parsed)
	}

	// An HTML filter exists to take markup out, so with no explicit action
	// the match is removed.
	if rule.HTMLFilter && !rule.HasAction {
		rule.Action = procOp{name: "remove"}
		rule.HasAction = true
	}

	return rule
}

// cssFunctionalPseudos are real CSS pseudo-classes that take arguments. Any
// other :name(...) at depth zero is treated as a procedural operator, so an
// unrecognised one gets the rule rejected instead of quietly becoming part of
// the base selector and matching nothing.
var cssFunctionalPseudos = map[string]bool{
	"not": true, "has": true, "is": true, "where": true, "matches-any": true,
	"nth-child": true, "nth-last-child": true, "nth-of-type": true,
	"nth-last-of-type": true, "lang": true, "dir": true, "host": true,
	"host-context": true, "state": true, "current": true,
}

// splitOperators divides a selector into the base CSS selector and the
// procedural operator chain. A colon only starts an operator at bracket and
// paren depth zero.
func splitOperators(sel string) (string, []string) {
	depth := 0
	inQuote := byte(0)
	var ops []string
	baseEnd := -1
	opStart := -1

	for i := 0; i < len(sel); i++ {
		c := sel[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inQuote = c
			continue
		case '[', '(':
			depth++
			continue
		case ']', ')':
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 || c != ':' {
			continue
		}
		name, _ := readIdentWhile(sel, i+1, func(b byte) bool {
			return b != '(' && b != ':' && b != '.' && b != '['
		})
		hasArgs := i+1+len(name) < len(sel) && sel[i+1+len(name)] == '('
		if !hasArgs {
			// A bare :pseudo-class such as :first-child stays in the base.
			continue
		}
		if !proceduralOps[name] && !unsupportedOps[name] && !cssFunctionalPseudos[name] {
			// Unknown functional pseudo: surface it as an operator so the
			// rule is rejected rather than silently inert.
			ops = append(ops, sel[i:matchParen(sel, i+1+len(name))+1])
			continue
		}
		if !proceduralOps[name] && !unsupportedOps[name] {
			continue
		}
		end := matchParen(sel, i+1+len(name)) + 1
		if baseEnd < 0 {
			baseEnd = i
		}
		if opStart < 0 {
			opStart = i
		}
		ops = append(ops, sel[opStart:end])
		opStart = end
		i = end - 1
	}

	if baseEnd < 0 {
		return sel, ops
	}
	return sel[:baseEnd], ops
}

func parseProcOp(raw string) (procOp, bool) {
	op := procOp{}
	if strings.HasPrefix(raw, ":") {
		raw = raw[1:]
	}
	if strings.HasPrefix(raw, "-") {
		op.neg = true
		raw = raw[1:]
	}

	if i := strings.IndexByte(raw, '('); i >= 0 {
		if !strings.HasSuffix(raw, ")") {
			return op, false
		}
		op.name = strings.ToLower(raw[:i])
		op.args = raw[i+1 : len(raw)-1]
	} else {
		op.name = strings.ToLower(raw)
	}

	if !proceduralOps[op.name] {
		return op, false
	}

	switch op.name {
	case "min-text-length":
		if n, err := strconv.Atoi(strings.TrimSpace(op.args)); err == nil {
			op.num = n
		}
	case "matches-attr", "matches-path", "others", "remove-attr", "remove-class":
		// The regex form is /pattern/. Otherwise the first argument is a
		// selector or attribute name and the compiled selector is used.
		first := firstArg(op.args)
		if len(first) > 1 && first[0] == '/' && first[len(first)-1] == '/' {
			if re, err := regexp.Compile("(?i)" + first[1:len(first)-1]); err == nil {
				op.re = re
			}
		} else if m := compileSelector(first); m != nil {
			op.inner = m
		}
	case "upward":
		if n, err := strconv.Atoi(strings.TrimSpace(op.args)); err == nil {
			op.num = n
			break
		}
		first := firstArg(op.args)
		if len(first) > 1 && first[0] == '/' && first[len(first)-1] == '/' {
			if re, err := regexp.Compile("(?i)" + first[1:len(first)-1]); err == nil {
				op.re = re
			}
		} else if m := compileSelector(first); m != nil {
			op.inner = m
		}
	case "not":
		_, inner := splitOperators(op.args)
		for _, raw := range inner {
			if nested, ok := parseProcOp(raw); ok {
				op.innerOps = append(op.innerOps, nested)
			}
		}
	}

	return op, true
}

func firstArg(args string) string {
	if i := strings.IndexByte(args, ','); i >= 0 {
		return strings.TrimSpace(args[:i])
	}
	return strings.TrimSpace(args)
}

func (r *ProceduralRule) appliesTo(domain string) bool {
	for _, d := range r.ExcludeDomains {
		if domainMatchesOrIsSubdomain(domain, d) {
			return false
		}
	}
	if len(r.IncludeDomains) > 0 {
		for _, d := range r.IncludeDomains {
			if domainMatchesOrIsSubdomain(domain, d) {
				return true
			}
		}
		return false
	}
	return true
}

// applyTo evaluates the rule against a parsed document, mutating it.
// Returns the number of nodes affected.
func (r *ProceduralRule) applyTo(doc *html.Node, pagePath string) int {
	matcher := compileSelector(r.BaseSelector)
	if matcher == nil {
		return 0
	}

	var candidates []*html.Node
	walkElements(doc, func(n *html.Node) {
		if matcher.matches(n) {
			candidates = append(candidates, n)
		}
	})

	// Operator chain narrows or redirects the candidate set; the action then
	// edits the survivors. :upward() is a redirect, not a filter — it moves
	// the target up the tree rather than rejecting nodes.
	kept := candidates
	for _, op := range r.Ops {
		if op.name == "upward" {
			kept = applyUpward(kept, op)
		} else {
			kept = applyFilter(kept, op, pagePath)
		}
		if len(kept) == 0 {
			return 0
		}
	}

	if !r.HasAction {
		// No action operator: the rule is really an element hiding rule, so
		// remember what matched and let the caller generate CSS for it.
		r.matched = kept
		return len(kept)
	}

	return applyAction(kept, r.Action)
}

func applyUpward(nodes []*html.Node, op procOp) []*html.Node {
	var out []*html.Node
	seen := make(map[*html.Node]bool)
	for _, n := range nodes {
		target := upwardTarget(n, op)
		if target == nil || seen[target] {
			continue
		}
		seen[target] = true
		out = append(out, target)
	}
	return out
}

func upwardTarget(n *html.Node, op procOp) *html.Node {
	if op.num > 0 {
		anc := n
		for i := 0; i < op.num; i++ {
			anc = parentElement(anc)
			if anc == nil {
				return nil
			}
		}
		return anc
	}
	if op.inner != nil {
		for a := parentElement(n); a != nil; a = parentElement(a) {
			if op.inner.matches(a) {
				return a
			}
		}
	}
	return nil
}

func applyFilter(nodes []*html.Node, op procOp, pagePath string) []*html.Node {
	var out []*html.Node
	for _, n := range nodes {
		if evalFilter(n, op, pagePath) != op.neg {
			out = append(out, n)
		}
	}
	return out
}

func evalFilter(n *html.Node, op procOp, pagePath string) bool {
	switch op.name {
	case "has-text":
		return strings.Contains(nodeText(n), op.args)
	case "min-text-length":
		return len(strings.TrimSpace(nodeText(n))) >= op.num
	case "matches-attr":
		return matchAttrOp(n, op)
	case "matches-css":
		return matchCSSOp(n, op)
	case "matches-path":
		if op.re != nil {
			return op.re.MatchString(pagePath)
		}
		return false
	case "upward":
		return matchUpward(n, op)
	case "others":
		return matchOthers(n, op)
	case "xpath":
		// Not implemented; treated as no match so the rule can't over-apply.
		return false
	case "not":
		// :not(:has-text(x)) — the nested chain is evaluated, then negated.
		if len(op.innerOps) == 0 {
			return false
		}
		res := false
		for _, inner := range op.innerOps {
			if evalFilter(n, inner, pagePath) {
				res = true
				break
			}
		}
		return !res
	}
	return false
}

func matchAttrOp(n *html.Node, op procOp) bool {
	if op.re != nil {
		for _, a := range n.Attr {
			if op.re.MatchString(a.Key) {
				return true
			}
		}
		return false
	}
	parts := strings.SplitN(op.args, ",", 2)
	attrName := strings.TrimSpace(parts[0])
	val, ok := lookupAttr(n, attrName)
	if !ok {
		return false
	}
	if len(parts) < 2 {
		return true
	}
	want := strings.TrimSpace(parts[1])
	if len(want) > 1 && want[0] == '/' && want[len(want)-1] == '/' {
		re, err := regexp.Compile(want[1 : len(want)-1])
		return err == nil && re.MatchString(val)
	}
	return val == want
}

func matchCSSOp(n *html.Node, op procOp) bool {
	style := attrValue(n, "style")
	if style == "" {
		return false
	}
	parts := strings.SplitN(op.args, ",", 2)
	prop := strings.TrimSpace(parts[0])
	decls := parseInlineStyle(style)
	got, ok := decls[strings.ToLower(prop)]
	if !ok {
		return false
	}
	if len(parts) < 2 {
		return true
	}
	want := strings.TrimSpace(parts[1])
	if len(want) > 1 && want[0] == '/' && want[len(want)-1] == '/' {
		re, err := regexp.Compile(want[1 : len(want)-1])
		return err == nil && re.MatchString(got)
	}
	return got == want
}

func parseInlineStyle(style string) map[string]string {
	out := make(map[string]string)
	for _, decl := range strings.Split(style, ";") {
		i := strings.IndexByte(decl, ':')
		if i < 0 {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(decl[:i]))] = strings.TrimSpace(decl[i+1:])
	}
	return out
}

func matchUpward(n *html.Node, op procOp) bool {
	return upwardTarget(n, op) != nil
}

// matchOthers reports whether n is the last of its siblings matching the inner
// selector, which is how uBlock reads :others().
func matchOthers(n *html.Node, op procOp) bool {
	if op.inner == nil || !op.inner.matches(n) {
		return false
	}
	for s := nextElementSibling(n); s != nil; s = nextElementSibling(s) {
		if op.inner.matches(s) {
			return false
		}
	}
	return true
}

func applyAction(nodes []*html.Node, op procOp) int {
	switch op.name {
	case "remove":
		count := 0
		for _, n := range nodes {
			if n.Parent != nil {
				n.Parent.RemoveChild(n)
				count++
			}
		}
		return count
	case "remove-attr":
		attrName := firstArg(op.args)
		if attrName == "" {
			return 0
		}
		for _, n := range nodes {
			removeAttr(n, attrName)
		}
		return len(nodes)
	case "remove-class":
		class := firstArg(op.args)
		if class == "" {
			return 0
		}
		for _, n := range nodes {
			removeClass(n, class)
		}
		return len(nodes)
	case "style":
		decls := parseInlineStyle(op.args)
		if len(decls) == 0 {
			return 0
		}
		for _, n := range nodes {
			applyInlineStyle(n, decls)
		}
		return len(nodes)
	}
	return 0
}

func removeAttr(n *html.Node, name string) {
	kept := n.Attr[:0]
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			continue
		}
		kept = append(kept, a)
	}
	n.Attr = kept
}

func removeClass(n *html.Node, class string) {
	cur := attrValue(n, "class")
	var kept []string
	for _, f := range strings.Fields(cur) {
		if f != class {
			kept = append(kept, f)
		}
	}
	if len(kept) == len(strings.Fields(cur)) {
		return
	}
	if len(kept) == 0 {
		removeAttr(n, "class")
		return
	}
	setAttr(n, "class", strings.Join(kept, " "))
}

func applyInlineStyle(n *html.Node, decls map[string]string) {
	cur := parseInlineStyle(attrValue(n, "style"))
	for k, v := range decls {
		cur[k] = v
	}
	parts := make([]string, 0, len(cur))
	for k, v := range cur {
		parts = append(parts, k+": "+v)
	}
	setAttr(n, "style", strings.Join(parts, "; "))
}

func setAttr(n *html.Node, name, val string) {
	for i := range n.Attr {
		if strings.EqualFold(n.Attr[i].Key, name) {
			n.Attr[i].Val = val
			return
		}
	}
	n.Attr = append(n.Attr, html.Attribute{Key: name, Val: val})
}

func walkElements(n *html.Node, fn func(*html.Node)) {
	if n.Type == html.ElementNode {
		fn(n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walkElements(c, fn)
	}
}
