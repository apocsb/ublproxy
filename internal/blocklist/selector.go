package blocklist

import (
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// Hand-rolled CSS selector matching, limited to the subset that shows up in
// adblock filters. Only needed server-side: browser-facing element hiding is
// injected as plain CSS and matched by the browser, which handles far more.
// The procedural engine uses this to find candidate nodes in the parsed
// document before running operator chains over them.

type selStep struct {
	combinator byte // combinator preceding this step: 0, ' ', '>', '+', '~'
	tag        string
	classes    []string
	id         string
	attrs      []attrTest
	pseudos    []pseudoTest
}

type attrTest struct {
	name  string
	op    string // "", "=", "^=", "$=", "*=", "~=", "|="
	value string
	re    *regexp.Regexp
}

type pseudoTest struct {
	name string
	// args holds the raw text inside the parentheses, already trimmed.
	// For :not() and :has() it is a nested selector, compiled lazily.
	sel  *selMatcher
	text string
}

// selMatcher holds a parsed selector list. Exported only so tests in the
// blocklist_test package can exercise it; production code goes through
// compileSelector.
type selMatcher struct {
	groups [][]selStep
}

// CompileSelector parses a selector list for use with Matches. Returns nil if
// the selector can't be parsed.
func CompileSelector(sel string) *selMatcher { return compileSelector(sel) }

// compileSelector parses a selector list. Returns nil if it can't be parsed,
// which makes the caller leave the rule alone rather than guess.
func compileSelector(sel string) *selMatcher {
	s := strings.TrimSpace(sel)
	if s == "" {
		return nil
	}
	m := &selMatcher{}
	for _, part := range splitTopLevel(s, ',') {
		steps := parseSelectorSeq(part)
		if len(steps) == 0 {
			return nil
		}
		m.groups = append(m.groups, steps)
	}
	if len(m.groups) == 0 {
		return nil
	}
	return m
}

// parseSelectorSeq parses a single compound-selector sequence.
func parseSelectorSeq(s string) []selStep {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}

	var steps []selStep
	pos := 0
	pendingCombinator := byte(0)

	for pos < len(s) {
		// Leading or repeated combinator.
		for pos < len(s) && isCombinatorChar(s[pos]) {
			if pendingCombinator == 0 || s[pos] == '>' || s[pos] == '+' || s[pos] == '~' {
				pendingCombinator = normalizeCombinator(s[pos])
			}
			pos++
		}
		// Leading combinator means "relative", e.g. the "> foo" in :has(> foo).
		if pos >= len(s) {
			break
		}

		step := selStep{combinator: pendingCombinator}
		pendingCombinator = 0
		pos = parseCompound(s, pos, &step)
		if step.tag == "" && step.id == "" && len(step.classes) == 0 &&
			len(step.attrs) == 0 && len(step.pseudos) == 0 {
			// Nothing consumed — bail rather than loop forever.
			break
		}
		steps = append(steps, step)
	}

	return steps
}

func isCombinatorChar(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '>' || c == '+' || c == '~'
}

func normalizeCombinator(c byte) byte {
	switch c {
	case '>', '+', '~':
		return c
	default:
		return ' '
	}
}

// parseCompound reads one compound selector starting at pos, filling step,
// and returns the new position.
func parseCompound(s string, pos int, step *selStep) int {
	start := pos
	for pos < len(s) && !isCombinatorChar(s[pos]) {
		switch s[pos] {
		case '#':
			pos++
			name, next := readIdent(s, pos)
			pos = next
			step.id = name
		case '.':
			pos++
			name, next := readIdent(s, pos)
			pos = next
			if name != "" {
				step.classes = append(step.classes, name)
			}
		case '[':
			var at attrTest
			pos, at = parseAttrTest(s, pos)
			if at.name != "" {
				step.attrs = append(step.attrs, at)
			}
		case ':':
			ps, next := parsePseudo(s, pos)
			pos = next
			if ps != nil {
				step.pseudos = append(step.pseudos, *ps)
			}
		case '*':
			// Universal selector. Kept as a distinct marker so an otherwise
			// empty compound still counts as consumed.
			if step.tag == "" {
				step.tag = "*"
			}
			pos++
		default:
			name, next := readIdent(s, pos)
			if name == "" {
				pos++
				continue
			}
			if step.tag == "" {
				step.tag = name
			}
			pos = next
		}
	}
	if pos == start {
		pos++
	}
	return pos
}

func readIdent(s string, pos int) (string, int) {
	start := pos
	for pos < len(s) && isIdentChar(s[pos]) {
		pos++
	}
	return s[start:pos], pos
}

func isIdentChar(c byte) bool {
	return c == '-' || c == '_' || c >= 0x80 ||
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func parseAttrTest(s string, pos int) (int, attrTest) {
	var at attrTest
	pos++ // '['
	// The name ends at the operator, so a name reader that only stopped at
	// '=' would swallow the '^' in [data-x^="y"].
	name, next := readIdentWhile(s, pos, func(c byte) bool {
		return c != ']' && c != '=' && c != '^' && c != '$' && c != '*' &&
			c != '~' && c != '|' && !isSpaceByte(c)
	})
	pos = next
	if name == "" {
		return pos, at
	}
	at.name = name
	for pos < len(s) && isSpaceByte(s[pos]) {
		pos++
	}
	// [attr] on its own is a presence test.
	if pos < len(s) && s[pos] == ']' {
		return pos + 1, at
	}
	// Optional operator, then the mandatory '='.
	switch {
	case pos < len(s) && s[pos] == '^':
		at.op = "^="
		pos++
	case pos < len(s) && s[pos] == '$':
		at.op = "$="
		pos++
	case pos < len(s) && s[pos] == '*':
		at.op = "*="
		pos++
	case pos < len(s) && s[pos] == '~':
		at.op = "~="
		pos++
	case pos < len(s) && s[pos] == '|':
		at.op = "|="
		pos++
	}
	for pos < len(s) && isSpaceByte(s[pos]) {
		pos++
	}
	if pos >= len(s) || s[pos] != '=' {
		// Malformed, treat as a presence test rather than guessing.
		at.op = ""
		return pos, at
	}
	if at.op == "" {
		at.op = "="
	}
	pos++
	for pos < len(s) && isSpaceByte(s[pos]) {
		pos++
	}
	if pos < len(s) && (s[pos] == '"' || s[pos] == '\'') {
		quote := s[pos]
		pos++
		vs := pos
		for pos < len(s) && s[pos] != quote {
			pos++
		}
		at.value = s[vs:pos]
		if pos < len(s) {
			pos++
		}
	} else {
		vs := pos
		for pos < len(s) && s[pos] != ']' && !isSpaceByte(s[pos]) {
			pos++
		}
		at.value = s[vs:pos]
	}
	for pos < len(s) && isSpaceByte(s[pos]) {
		pos++
	}
	if pos < len(s) && s[pos] == ']' {
		pos++
	}
	if strings.HasPrefix(at.value, "/") && strings.HasSuffix(at.value, "/") && len(at.value) > 1 {
		if re, err := regexp.Compile("^(?:" + at.value[1:len(at.value)-1] + ")$"); err == nil {
			at.re = re
		}
	}
	return pos, at
}

func readIdentWhile(s string, pos int, ok func(byte) bool) (string, int) {
	start := pos
	for pos < len(s) && ok(s[pos]) {
		pos++
	}
	return s[start:pos], pos
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}

func parsePseudo(s string, pos int) (*pseudoTest, int) {
	pos++ // ':'
	// Pseudo-elements and vendor prefixes we don't act on.
	if pos < len(s) && s[pos] == ':' {
		return nil, pos + 1
	}
	name, next := readIdentWhile(s, pos, func(c byte) bool { return c != '(' && c != ':' })
	pos = next
	pt := &pseudoTest{name: strings.ToLower(name)}

	if pos < len(s) && s[pos] == ':' {
		// Something like :nth-child(2n) — read the parenthesised part and
		// treat the whole thing as an opaque predicate we can't evaluate.
		pt.name = "unsupported"
	}

	if pos < len(s) && s[pos] == '(' {
		end := matchParen(s, pos)
		pt.text = strings.TrimSpace(s[pos+1 : end])
		pos = end + 1
		if pt.name == "not" || pt.name == "has" || pt.name == "matches-any" {
			if nested := compileSelector(pt.text); nested != nil {
				pt.sel = nested
			} else {
				pt.name = "unsupported"
			}
		}
	}
	return pt, pos
}

// matchParen returns the index of the ')' closing the '(' at pos.
func matchParen(s string, pos int) int {
	depth := 0
	inQuote := byte(0)
	for i := pos; i < len(s); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inQuote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return len(s) - 1
}

// splitTopLevel splits on sep, ignoring separators inside brackets, parens
// and quotes.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth := 0
	inQuote := byte(0)
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			inQuote = c
		case '[', '(':
			depth++
		case ']', ')':
			if depth > 0 {
				depth--
			}
		case sep:
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// matches reports whether n is an element selected by this matcher.
func (m *selMatcher) Matches(n *html.Node) bool { return m.matches(n) }

// matches reports whether n is an element selected by this matcher.
func (m *selMatcher) matches(n *html.Node) bool {
	if m == nil || n == nil || n.Type != html.ElementNode {
		return false
	}
	for _, group := range m.groups {
		if matchSeq(group, n) {
			return true
		}
	}
	return false
}

// matchSeq reports whether the whole sequence matches, anchored on n for its
// final step.
func matchSeq(steps []selStep, n *html.Node) bool {
	if len(steps) == 0 {
		return false
	}
	last := steps[len(steps)-1]
	if !matchStep(last, n) {
		return false
	}
	return matchRest(steps[:len(steps)-1], last.combinator, n)
}

// matchRest places the remaining steps at whatever relates to n through comb.
// The combinator belongs to the step that was just placed, not to the step
// being placed — that distinction is what makes "a + b" match b and not a.
func matchRest(steps []selStep, comb byte, n *html.Node) bool {
	if len(steps) == 0 {
		return true
	}

	var candidates []*html.Node
	switch comb {
	case '>':
		if p := parentElement(n); p != nil {
			candidates = []*html.Node{p}
		}
	case '+':
		if s := siblingBefore(n, false); s != nil {
			candidates = []*html.Node{s}
		}
	case '~':
		candidates = siblingsBefore(n)
	case 0:
		// The sequence's first step matches the node itself.
		candidates = []*html.Node{n}
	default:
		for a := parentElement(n); a != nil; a = parentElement(a) {
			candidates = append(candidates, a)
		}
	}

	last := steps[len(steps)-1]
	rest := steps[:len(steps)-1]
	for _, c := range candidates {
		if matchStep(last, c) && matchRest(rest, last.combinator, c) {
			return true
		}
	}
	return false
}

func matchStep(step selStep, n *html.Node) bool {
	if n == nil || n.Type != html.ElementNode {
		return false
	}
	if step.tag != "" && step.tag != "*" && !strings.EqualFold(step.tag, n.Data) {
		return false
	}
	if step.id != "" && attrValue(n, "id") != step.id {
		return false
	}
	for _, c := range step.classes {
		if !hasClass(n, c) {
			return false
		}
	}
	for _, at := range step.attrs {
		if !matchAttr(at, n) {
			return false
		}
	}
	for _, ps := range step.pseudos {
		if !matchPseudo(ps, n) {
			return false
		}
	}
	return true
}

func matchAttr(at attrTest, n *html.Node) bool {
	val, ok := lookupAttr(n, at.name)
	if !ok {
		return false
	}
	if at.re != nil {
		return at.re.MatchString(val)
	}
	switch at.op {
	case "":
		return true
	case "=":
		return val == at.value
	case "^=":
		return at.value != "" && strings.HasPrefix(val, at.value)
	case "$=":
		return at.value != "" && strings.HasSuffix(val, at.value)
	case "*=":
		return at.value != "" && strings.Contains(val, at.value)
	case "~=":
		return containsField(val, at.value)
	case "|=":
		return val == at.value || strings.HasPrefix(val, at.value+"-")
	}
	return false
}

func matchPseudo(ps pseudoTest, n *html.Node) bool {
	switch ps.name {
	case "not":
		if ps.sel == nil {
			return true
		}
		return !ps.sel.matches(n)
	case "has":
		if ps.sel == nil {
			return false
		}
		return matchHas(ps.sel, n)
	case "first-child":
		return previousElementSibling(n) == nil
	case "last-child":
		return nextElementSibling(n) == nil
	case "only-child":
		return previousElementSibling(n) == nil && nextElementSibling(n) == nil
	case "empty":
		return nodeText(n) == ""
	case "root":
		return n.Parent == nil || n.Parent.Type == html.DocumentNode
	}
	// Anything we can't evaluate must not match, or we'd hide too much.
	return false
}

// matchHas implements :has(). Its argument is a relative selector anchored at
// n, so a leading combinator points away from n in document order: "> p" is a
// child, "+ p" the next sibling, "~ p" any following sibling.
func matchHas(m *selMatcher, n *html.Node) bool {
	for _, group := range m.groups {
		steps := make([]selStep, len(group))
		copy(steps, group)
		scope := hasScope(steps[0].combinator, n)
		steps[0].combinator = 0
		for _, c := range scope {
			if matchSeq(steps, c) {
				return true
			}
		}
	}
	return false
}

// hasScope returns the nodes a relative selector inside :has() may match.
func hasScope(combinator byte, n *html.Node) []*html.Node {
	switch combinator {
	case '>':
		var out []*html.Node
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode {
				out = append(out, c)
			}
		}
		return out
	case '+':
		if s := nextElementSibling(n); s != nil {
			return []*html.Node{s}
		}
		return nil
	case '~':
		var out []*html.Node
		for s := nextElementSibling(n); s != nil; s = nextElementSibling(s) {
			out = append(out, s)
		}
		return out
	default:
		// No combinator, or a descendant one: the anchor and its subtree.
		out := []*html.Node{n}
		var walk func(*html.Node)
		walk = func(node *html.Node) {
			for c := node.FirstChild; c != nil; c = c.NextSibling {
				if c.Type != html.ElementNode {
					continue
				}
				out = append(out, c)
				walk(c)
			}
		}
		walk(n)
		return out
	}
}

func parentElement(n *html.Node) *html.Node {
	if n == nil {
		return nil
	}
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Type == html.ElementNode {
			return p
		}
	}
	return nil
}

// siblingBefore returns the element sibling before n, or nil. When any is
// false it skips over text and comment nodes.
func siblingBefore(n *html.Node, any bool) *html.Node {
	for s := n.PrevSibling; s != nil; s = s.PrevSibling {
		if s.Type == html.ElementNode {
			return s
		}
		if any {
			return s
		}
	}
	return nil
}

func siblingsBefore(n *html.Node) []*html.Node {
	var out []*html.Node
	for s := n.PrevSibling; s != nil; s = s.PrevSibling {
		if s.Type == html.ElementNode {
			out = append(out, s)
		}
	}
	return out
}

func previousElementSibling(n *html.Node) *html.Node { return siblingBefore(n, false) }

func nextElementSibling(n *html.Node) *html.Node {
	for s := n.NextSibling; s != nil; s = s.NextSibling {
		if s.Type == html.ElementNode {
			return s
		}
	}
	return nil
}

func lookupAttr(n *html.Node, name string) (string, bool) {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, name) {
			return a.Val, true
		}
	}
	return "", false
}

func attrValue(n *html.Node, name string) string {
	v, _ := lookupAttr(n, name)
	return v
}

func hasClass(n *html.Node, class string) bool {
	return containsField(attrValue(n, "class"), class)
}

func containsField(list, want string) bool {
	for _, f := range strings.Fields(list) {
		if f == want {
			return true
		}
	}
	return false
}

// nodeText returns the concatenated text of n and its descendants.
func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			b.WriteString(node.Data)
			return
		}
		if node.Type != html.ElementNode && node.Type != html.DocumentNode {
			return
		}
		for c := node.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}
