package blocklist

import "strings"

// ScriptletSource returns the JavaScript source for a scriptlet by name,
// with the given arguments substituted. Returns empty string if unknown.
func ScriptletSource(name string, args []string) string {
	// Normalize aliases
	canonical, ok := scriptletAliases[name]
	if ok {
		name = canonical
	}

	tmpl, ok := scriptletLibrary[name]
	if !ok {
		return ""
	}

	return tmpl(args)
}

// ScriptletAliases returns the short names accepted in ##+js() rules.
func ScriptletAliases() []string {
	names := make([]string, 0, len(scriptletAliases))
	for name := range scriptletAliases {
		names = append(names, name)
	}
	return names
}

// ScriptletNames returns every scriptlet name the library can generate.
func ScriptletNames() []string {
	names := make([]string, 0, len(scriptletLibrary))
	for name := range scriptletLibrary {
		names = append(names, name)
	}
	return names
}

// CanonicalScriptletName resolves an alias to its canonical name.
func CanonicalScriptletName(name string) string {
	if canonical, ok := scriptletAliases[name]; ok {
		return canonical
	}
	return name
}

// scriptletAliases maps short names to canonical scriptlet names.
var scriptletAliases = map[string]string{
	"set":  "set-constant",
	"aopr": "abort-on-property-read",
	"aopw": "abort-on-property-write",
	"acis": "abort-current-inline-script",
	"aeld": "addEventListener-defuser",
	"ra":   "remove-attr",
	"rc":   "remove-class",
}

// scriptletLibrary maps scriptlet names to template functions that generate
// executable JavaScript. Each function takes the arguments from the filter
// rule and returns a self-contained IIFE.
var scriptletLibrary = map[string]func([]string) string{
	"set-constant": func(args []string) string {
		if len(args) < 2 {
			return ""
		}
		prop := jsStringEscape(args[0])
		value := args[1]
		jsValue := resolveConstantValue(value)
		return `(function() {
	var prop = '` + prop + `';
	var value = ` + jsValue + `;
	var chain = prop.split('.');
	var owner = window;
	for (var i = 0; i < chain.length - 1; i++) {
		if (!(chain[i] in owner)) { owner[chain[i]] = {}; }
		owner = owner[chain[i]];
	}
	var key = chain[chain.length - 1];
	try {
		Object.defineProperty(owner, key, {
			configurable: false,
			get: function() { return value; },
			set: function() {}
		});
	} catch(e) { owner[key] = value; }
})();
`
	},

	"abort-on-property-read": func(args []string) string {
		if len(args) < 1 {
			return ""
		}
		prop := jsStringEscape(args[0])
		return `(function() {
	var prop = '` + prop + `';
	var chain = prop.split('.');
	var owner = window;
	for (var i = 0; i < chain.length - 1; i++) {
		if (!(chain[i] in owner)) { owner[chain[i]] = {}; }
		owner = owner[chain[i]];
	}
	var key = chain[chain.length - 1];
	Object.defineProperty(owner, key, {
		configurable: true,
		get: function() { throw new ReferenceError(prop); },
		set: function() {}
	});
})();
`
	},

	"abort-on-property-write": func(args []string) string {
		if len(args) < 1 {
			return ""
		}
		prop := jsStringEscape(args[0])
		return `(function() {
	var prop = '` + prop + `';
	var chain = prop.split('.');
	var owner = window;
	for (var i = 0; i < chain.length - 1; i++) {
		if (!(chain[i] in owner)) { owner[chain[i]] = {}; }
		owner = owner[chain[i]];
	}
	var key = chain[chain.length - 1];
	var existing = owner[key];
	Object.defineProperty(owner, key, {
		configurable: true,
		get: function() { return existing; },
		set: function() { throw new ReferenceError(prop); }
	});
})();
`
	},

	"abort-current-inline-script": func(args []string) string {
		if len(args) < 1 {
			return ""
		}
		prop := jsStringEscape(args[0])
		needle := ""
		if len(args) >= 2 {
			needle = jsStringEscape(args[1])
		}
		return `(function() {
	var prop = '` + prop + `';
	var needle = '` + needle + `';
	var chain = prop.split('.');
	var owner = window;
	for (var i = 0; i < chain.length - 1; i++) {
		if (!(chain[i] in owner)) { return; }
		owner = owner[chain[i]];
	}
	var key = chain[chain.length - 1];
	var existing = owner[key];
	Object.defineProperty(owner, key, {
		configurable: true,
		get: function() {
			if (needle === '' || (document.currentScript && document.currentScript.textContent.indexOf(needle) !== -1)) {
				throw new ReferenceError(prop);
			}
			return existing;
		},
		set: function(v) { existing = v; }
	});
})();
`
	},

	"addEventListener-defuser": func(args []string) string {
		typeNeedle := ""
		handlerNeedle := ""
		if len(args) >= 1 {
			typeNeedle = jsStringEscape(args[0])
		}
		if len(args) >= 2 {
			handlerNeedle = jsStringEscape(args[1])
		}
		return `(function() {
	var typeNeedle = '` + typeNeedle + `';
	var handlerNeedle = '` + handlerNeedle + `';
	var orig = EventTarget.prototype.addEventListener;
	EventTarget.prototype.addEventListener = function(type, handler, options) {
		if (typeNeedle !== '' && type.indexOf(typeNeedle) === -1) {
			return orig.call(this, type, handler, options);
		}
		if (handlerNeedle !== '' && (typeof handler === 'function') && handler.toString().indexOf(handlerNeedle) === -1) {
			return orig.call(this, type, handler, options);
		}
	};
})();
`
	},

	"nowebrtc": func(args []string) string {
		return `(function() {
	if (typeof window.RTCPeerConnection === 'function') {
		window.RTCPeerConnection = function() { throw new DOMException('blocked by ublproxy'); };
	}
	if (typeof window.webkitRTCPeerConnection === 'function') {
		window.webkitRTCPeerConnection = function() { throw new DOMException('blocked by ublproxy'); };
	}
})();
`
	},

	"no-setTimeout-if": func(args []string) string {
		needle := ""
		delay := ""
		if len(args) >= 1 {
			needle = jsStringEscape(args[0])
		}
		if len(args) >= 2 {
			delay = jsStringEscape(args[1])
		}
		return `(function() {
	var needle = '` + needle + `';
	var delay = '` + delay + `';
	var orig = window.setTimeout;
	window.setTimeout = function(fn, ms) {
		var s = typeof fn === 'function' ? fn.toString() : String(fn);
		if (needle !== '' && s.indexOf(needle) !== -1) {
			if (delay === '' || String(ms) === delay) { return; }
		}
		return orig.apply(this, arguments);
	};
})();
`
	},

	"no-setInterval-if": func(args []string) string {
		needle := ""
		delay := ""
		if len(args) >= 1 {
			needle = jsStringEscape(args[0])
		}
		if len(args) >= 2 {
			delay = jsStringEscape(args[1])
		}
		return `(function() {
	var needle = '` + needle + `';
	var delay = '` + delay + `';
	var orig = window.setInterval;
	window.setInterval = function(fn, ms) {
		var s = typeof fn === 'function' ? fn.toString() : String(fn);
		if (needle !== '' && s.indexOf(needle) !== -1) {
			if (delay === '' || String(ms) === delay) { return; }
		}
		return orig.apply(this, arguments);
	};
})();
`
	},

	"prevent-fetch": func(args []string) string {
		needle := ""
		if len(args) >= 1 {
			needle = jsStringEscape(args[0])
		}
		return `(function() {
	var needle = '` + needle + `';
	var origFetch = window.fetch;
	window.fetch = function(resource, init) {
		var url = typeof resource === 'string' ? resource : (resource && resource.url ? resource.url : '');
		if (needle === '' || url.indexOf(needle) !== -1) {
			return Promise.resolve(new Response('', {status: 200, statusText: 'OK'}));
		}
		return origFetch.apply(this, arguments);
	};
})();
`
	},

	"json-prune": func(args []string) string {
		prunePaths := splitPruneArg(args, 0)
		needlePaths := splitPruneArg(args, 1)
		if prunePaths == "" {
			return ""
		}
		// uBlock's json-prune signature is `json-prune, prunePaths, needlePaths`.
		// The second argument is optional and is the only precondition: when it
		// is absent the paths are pruned unconditionally, and when it is present
		// every one of its paths must exist before anything is removed. Filter
		// text carrying a single comma therefore prunes blindly, which is how
		// uBlock's own YouTube rule deletes both the wrapped and the bare form of
		// a key from the same payload.
		return `(function() {
	var prunePaths = '` + jsStringEscape(prunePaths) + `'.split(' ').filter(Boolean);
	var needlePaths = '` + jsStringEscape(needlePaths) + `'.split(' ').filter(Boolean);
	var own = Object.prototype.hasOwnProperty;
	// Walks a dotted path, optionally deleting what it finds. Mirrors uBlock's
	// objectFindOwner so filters written for the extension behave the same here.
	var findOwner = function(root, chain, prune) {
		if (root === null || typeof root !== 'object') { return false; }
		var dot = chain.indexOf('.');
		var prop = dot === -1 ? chain : chain.slice(0, dot);
		var next = dot === -1 ? '' : chain.slice(dot + 1);
		var i, keys, found;
		if (prop === '[-]' && Array.isArray(root)) {
			found = false;
			for (i = root.length; i--;) {
				if (findOwner(root[i], next, prune) === false) { continue; }
				if (prune) { root.splice(i, 1); }
				found = true;
			}
			return found;
		}
		if (prop === '{-}') {
			found = false;
			keys = Object.keys(root);
			for (i = 0; i < keys.length; i++) {
				if (findOwner(root[keys[i]], next, prune) === false) { continue; }
				if (prune) { delete root[keys[i]]; }
				found = true;
			}
			return found;
		}
		if (prop === '*' && next === '') {
			keys = Object.keys(root);
			for (i = 0; i < keys.length; i++) {
				if (prune) { delete root[keys[i]]; }
			}
			return true;
		}
		if ((prop === '[]' && Array.isArray(root)) ||
			((prop === '{}' || prop === '*') && root instanceof Object)) {
			found = false;
			keys = Object.keys(root);
			for (i = 0; i < keys.length; i++) {
				if (findOwner(root[keys[i]], next, prune) === false) { continue; }
				found = true;
			}
			return found;
		}
		if (own.call(root, prop) === false) { return false; }
		if (next === '') {
			if (prune) { delete root[prop]; }
			return true;
		}
		return findOwner(root[prop], next, prune);
	};
	var prune = function(obj) {
		if (obj === null || typeof obj !== 'object') { return obj; }
		for (var n = 0; n < needlePaths.length; n++) {
			if (findOwner(obj, needlePaths[n], false) === false) { return obj; }
		}
		for (var p = 0; p < prunePaths.length; p++) {
			findOwner(obj, prunePaths[p], true);
		}
		return obj;
	};
	// YouTube and most modern sites read API responses through Response.json(),
	// so JSON.parse alone catches nothing.
	JSON.parse = new Proxy(JSON.parse, {
		apply: function(target, thisArg, args) { return prune(Reflect.apply(target, thisArg, args)); }
	});
	if (typeof Response === 'function' && Response.prototype) {
		Response.prototype.json = new Proxy(Response.prototype.json, {
			apply: function(target, thisArg, args) {
				return Reflect.apply(target, thisArg, args).then(prune);
			}
		});
	}
	// YouTube does not send the player's ad schedule as JSON over the wire. It
	// assigns an inline object literal to a global and hands that object
	// straight to the player as raw_player_response, so neither hook above can
	// see it. Intercept the assignment instead: defining an accessor puts the
	// property on window first, so the page's own "var" declaration finds it
	// already there and routes its initializer through the setter rather than
	// redefining it.
	try {
		var slot = { value: prune(window.ytInitialPlayerResponse) };
		Object.defineProperty(window, 'ytInitialPlayerResponse', {
			configurable: true,
			get: function() { return slot.value; },
			set: function(val) { slot.value = prune(val); }
		});
	} catch (e) { /* window not extensible, or property is locked down */ }
})();
`
	},

	"remove-class": func(args []string) string {
		if len(args) < 1 {
			return ""
		}
		class := jsStringEscape(args[0])
		selector := ""
		if len(args) >= 2 {
			selector = jsStringEscape(args[1])
		}
		return `(function() {
	var cls = '` + class + `';
	var selector = '` + selector + `' || '[' + cls + ']';
	var remove = function() {
		var els = document.querySelectorAll(selector);
		for (var i = 0; i < els.length; i++) { els[i].classList.remove(cls); }
	};
	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', remove);
	} else {
		remove();
	}
	new MutationObserver(remove).observe(document.documentElement, {childList: true, subtree: true, attributes: true});
})();
`
	},

	"remove-attr": func(args []string) string {
		if len(args) < 1 {
			return ""
		}
		attr := jsStringEscape(args[0])
		selector := ""
		if len(args) >= 2 {
			selector = jsStringEscape(args[1])
		}
		return `(function() {
	var attr = '` + attr + `';
	var selector = '` + selector + `' || '[' + attr + ']';
	var remove = function() {
		var els = document.querySelectorAll(selector);
		for (var i = 0; i < els.length; i++) { els[i].removeAttribute(attr); }
	};
	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', remove);
	} else {
		remove();
	}
	var observer = new MutationObserver(remove);
	observer.observe(document.documentElement, {childList: true, subtree: true, attributes: true});
})();
`
	},
}

// splitPruneArg returns the nth space-separated prune argument, or "" if absent.
func splitPruneArg(args []string, n int) string {
	if len(args) <= n {
		return ""
	}
	return strings.TrimSpace(args[n])
}

// resolveConstantValue maps uBO constant names to JavaScript expressions.
func resolveConstantValue(val string) string {
	switch val {
	case "true":
		return "true"
	case "false":
		return "false"
	case "undefined":
		return "undefined"
	case "null":
		return "null"
	case "noopFunc":
		return "(function(){})"
	case "trueFunc":
		return "(function(){return true})"
	case "falseFunc":
		return "(function(){return false})"
	case "''", `""`:
		return "''"
	case "0":
		return "0"
	case "1":
		return "1"
	case "-1":
		return "-1"
	case "[]":
		return "[]"
	case "{}":
		return "{}"
	case "NaN":
		return "NaN"
	default:
		return "'" + jsStringEscape(val) + "'"
	}
}

// jsStringEscape escapes a string for safe inclusion in a JS single-quoted string.
func jsStringEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "</script", `<\/script`)
	return s
}
