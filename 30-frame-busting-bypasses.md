# 30 - Frame Busting: JavaScript Anti-Clickjacking and Its Bypasses

## Frame Busting — The JavaScript Defense

Frame busting is a client-side defense where a page detects it's loaded in an iframe and breaks out:

```javascript
if (top.location != location) {
    top.location = self.location;
}
```

If the page is framed (`top` is not `self`), it replaces the top-level page with itself, escaping the iframe.

## Common Frame Busting Variations

### Detection Conditions

```javascript
if (top != self)
if (top.location != self.location)
if (top.location != location)
if (parent.frames.length > 0)
if (window != top)
if (window.top !== window.self)
if (window.self != window.top)
if (parent && parent != window)
if (parent && parent.frames && parent.frames.length > 0)
if ((self.parent && !(self.parent === self)) && (self.parent.frames.length != 0))
```

All of these try to answer the same question: "Am I inside an iframe?"

### Breakout Actions

```javascript
top.location = self.location
top.location.href = document.location.href
top.location.href = self.location.href
top.location.replace(self.location)
top.location.replace(document.location)
top.location.href = window.location.href
top.location.href = "URL"
top.location = location
top.location = window.location
top.location.replace(window.location.pathname)
window.top.location = window.self.location
self.parent.location = document.location
parent.location.href = self.document.location
var url = window.location.href; top.location.replace(url)
```

### Nuclear Options (Destroy Page Content)

```javascript
document.write('')
setTimeout(function(){ document.body.innerHTML = ''; }, 1);
window.self.onload = function(evt){ document.body.innerHTML = ''; }
```

If the page can't break out, it destroys its own content so the attacker can't use it.

## Why Frame Busting Is Unreliable

### Bypass 1: `parent.location` vs `top.location`

Some frame busting code uses `parent.location` instead of `top.location`:

```javascript
if (top.location != self.location) {
    parent.location = self.location;
}
```

**The double-framing bypass:**

```
Attacker top frame:
  <iframe src="attacker2.html">
    Attacker sub-frame:
      <iframe src="http://www.victim.com">
```

The victim page sets `parent.location = self.location`, which navigates the **middle frame** (attacker2.html) to the victim page. But `top` (the attacker's outer page) remains intact — the clickjacking still works. The victim page is now framed by the outer attacker page, and the frame busting code ran against the wrong parent.

Using `top.location` would prevent this, but `top.location` has its own problems (same-origin policy may block reading `top.location` cross-origin).

### Bypass 2: Sandbox Attribute

```html
<iframe src="http://victim.com" sandbox="allow-forms"></iframe>
```

The HTML5 `sandbox` attribute disables JavaScript in the iframe by default. The frame busting code never executes, but forms still work (if `allow-forms` is set), so clickjacking on form submissions still succeeds.

### Bypass 3: `onbeforeunload` Cancellation

```javascript
window.onbeforeunload = function() {
    return "Are you sure you want to leave?";
}
```

The attacker's parent page sets `onbeforeunload`. When the victim's frame busting code tries `top.location = ...`, the browser shows a confirmation dialog. If the user clicks "Stay on page", the navigation is cancelled and the frame busting fails.

### Bypass 4: Disabling JavaScript Entirely

If the attacker can convince the user to disable JavaScript (or uses a browser/extension setting), all frame busting code is inert.

### Bypass 5: IE Restricted Zone

```html
<iframe src="http://victim.com" security="restricted"></iframe>
```

IE's `security="restricted"` attribute disables JavaScript in the iframe, similar to `sandbox`.

## Why Server-Side Defenses Win

| Defense | Can be bypassed by attacker? |
|---------|------------------------------|
| Frame busting (JavaScript) | Yes — sandbox, onbeforeunload, double-framing, JS disabled |
| `X-Frame-Options: DENY` | No — enforced by the browser before any content renders |
| CSP `frame-ancestors 'none'` | No — enforced by the browser before any content renders |

**Frame busting is defense-in-depth at best.** The real protection is `X-Frame-Options` or CSP `frame-ancestors`, which are enforced by the browser at the HTTP header level — no JavaScript needed, no bypasses possible.

## How CSP `frame-ancestors` Works — From Server to Browser

### Step 1: Server Sets the HTTP Header

The server includes the CSP header in every HTTP response:

**Nginx:**
```nginx
add_header Content-Security-Policy "frame-ancestors 'none'";
```

**Apache:**
```apache
Header always set Content-Security-Policy "frame-ancestors 'none'"
```

**Node.js / Express:**
```javascript
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
    next();
});
```

**Java / Spring:**
```java
response.setHeader("Content-Security-Policy", "frame-ancestors 'none'");
```

### Step 2: The HTTP Response

```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Security-Policy: frame-ancestors 'none'

<!DOCTYPE html>
<html>...
```

The header travels with the response before the browser processes any HTML or JavaScript.

### Step 3: Browser Enforcement Flow

```
Attacker page                         Browser                              Target server
─────────────                         ───────                              ─────────────
<iframe src="target.com">
         ──── GET /page ──────────────────────────────────────────────────►
                                                                           200 OK
         ◄──────────────────────────────── Content-Security-Policy: ────────
                                           frame-ancestors 'none'

                                      ┌──────────────────────────────┐
                                      │ CHECK: Is this response      │
                                      │ being loaded in a frame?     │
                                      │                              │
                                      │ YES → Is the parent origin   │
                                      │ allowed by frame-ancestors?  │
                                      │                              │
                                      │ 'none' → NO origin allowed   │
                                      │                              │
                                      │ ✗ BLOCK: Refuse to render    │
                                      │   the response content       │
                                      └──────────────────────────────┘

                                      Browser shows blank iframe
                                      or an error. No content is
                                      ever rendered or executed.
```

**The critical point:** The browser checks the policy **after receiving the response but before rendering any content**. The HTML is never parsed, JavaScript never executes, and no DOM is created. There is nothing for the attacker to interact with.

### Step 4: What the Attacker Sees

The iframe remains empty. The browser may show a console error:

```
Refused to display 'https://target.com/' in a frame because an ancestor
violates the following Content Security Policy directive: "frame-ancestors 'none'".
```

### `frame-ancestors` Values

| Value | Effect |
|-------|--------|
| `'none'` | Cannot be framed by anyone |
| `'self'` | Only framed by same-origin pages |
| `https://trusted.com` | Only framed by the specified origin |
| `https://*.trusted.com` | Only framed by subdomains of trusted.com |
| `'self' https://partner.com` | Same-origin or the specific partner |

### `frame-ancestors` vs `X-Frame-Options`

| | `X-Frame-Options` | CSP `frame-ancestors` |
|---|-------------------|----------------------|
| **Values** | `DENY`, `SAMEORIGIN`, `ALLOW-FROM uri` | Any combination of origins, `'self'`, `'none'` |
| **Multiple origins** | No (`ALLOW-FROM` takes one URI) | Yes (space-separated list) |
| **Wildcard subdomains** | No | Yes (`*.example.com`) |
| **Standard** | Never formally standardized (de facto) | W3C standard (CSP Level 2+) |
| **Browser support** | Universal (legacy) | All modern browsers |
| **Precedence** | Ignored if `frame-ancestors` is present | Takes priority over `X-Frame-Options` |

**Recommendation:** Use `frame-ancestors` as the primary defense. Add `X-Frame-Options` as a fallback for very old browsers. If both are present, `frame-ancestors` takes precedence.

