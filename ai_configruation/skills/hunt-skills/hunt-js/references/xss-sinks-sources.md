# DOM XSS Sinks & Sources

Heuristic pass only — flags candidates for manual confirmation in the actual
page/DevTools, not proven vulnerabilities.

## Dangerous sinks
- `\.innerHTML\s*=`
- `\.outerHTML\s*=`
- `document\.write(ln)?\(`
- `\beval\(`
- `new Function\(`
- `setTimeout\(\s*["'\`]` / `setInterval\(\s*["'\`]` (string arg, not a function ref)
- `\.insertAdjacentHTML\(`
- `\.html\(` (jQuery)
- `dangerouslySetInnerHTML` (React — means the guardrail was deliberately bypassed)
- `location\s*=` / `location\.href\s*=` / `location\.replace\(` / `location\.assign\(`
- `document\.domain\s*=`
- `\.setAttribute\(\s*["']href["']` combined with unsanitized input (`javascript:` sink)
- `execCommand\(`

## Tainted sources (user-influenceable)
- `location\.hash`
- `location\.search`
- `location\.href` (as a read)
- `document\.URL`
- `document\.referrer`
- `window\.name`
- `postMessage` handler: `addEventListener\(\s*["']message["']` — then check
  whether the handler validates `event.origin` before touching `event.data`
- `localStorage\.getItem\(` / `sessionStorage\.getItem\(` (taint if the stored
  value could itself come from a URL param elsewhere in the app)
- URL query param parsing helpers (`URLSearchParams`, custom `getParam`/`qs`
  helpers)

## Heuristic correlation
When a source and a sink appear in the same function body, or within ~15
lines of each other and clearly share a variable, elevate it:
"`<var>` read from `<source>` around line X flows into `<sink>` around line
Y — worth checking by hand." Don't claim confirmed exploitability.

## postMessage-specific check
If a `message` event listener is found, explicitly note whether it checks
`event.origin` (or a wildcard/missing check) — missing origin validation
feeding into a sink is one of the highest-value DOM XSS patterns to flag.

## Common false positives
- Sinks fed only by hardcoded string literals with no source nearby
- Sanitizer calls wrapping the source before the sink (`DOMPurify.sanitize(`,
  `escapeHtml(`, `encodeURIComponent(` immediately around the tainted value) —
  still mention but mark as "likely sanitized, lower priority"
