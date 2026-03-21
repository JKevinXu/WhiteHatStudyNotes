# 20 - URL Context XSS and Protocol-Based Attacks

## CSS Context Encoding (Recap)

CSS injection vectors like `@import`, `expression()`, `-moz-binding`, and `behavior` require proper CSS encoding:

```java
String safe = ESAPI.encoder().encodeForCSS(request.getParameter("input"));
```

## URL Attribute Injection

### Breaking Out of `href`

```html
<a href="http://www.evil.com/?test=" onclick=alert(1)"">test</a>
```

The attacker closes the `href` attribute with a quote, then injects a new `onclick` event handler.

**Defense — URL encoding:**

```html
<a href="http://www.evil.com/?test=%22%20onclick%3balert%281%29%22">test</a>
```

URL encoding (`%22` for `"`, `%3b` for `;`) prevents the value from breaking out of the attribute.

## URL Structure

```
[Protocol][Host][Path][Search][Hash]
```

Example:

```
https://www.evil.com/a/b/c/test?abc=123#ssss

[Protocol] = "https://"
[Host]     = "www.evil.com"
[Path]     = "/a/b/c/test"
[Search]   = "?abc=123"
[Hash]     = "#ssss"
```

### Protocol (Scheme)

The **Protocol** is the part before `://` that tells the browser **how to handle** the resource. The browser's behavior changes entirely based on which protocol is used:

| Protocol | Behavior |
|----------|----------|
| `https://` | Fetch resource over encrypted HTTP |
| `http://` | Fetch resource over plain HTTP |
| `javascript:` | Execute the rest of the URL as JavaScript code |
| `data:` | Interpret the rest of the URL as inline data |
| `ftp://` | File transfer protocol |
| `file://` | Access local filesystem |

For `https://example.com`, the browser makes a network request. But for `javascript:alert(document.cookie)`, it **runs the code** directly — no network request at all. This is why controlling the protocol is the key to URL-based XSS.

## Dangerous Protocol Schemes

When `$var` controls the entire `href`:

```html
<a href="$var">test</a>
```

### `javascript:` Protocol

```html
<a href="javascript:alert(1);">test</a>
```

Clicking the link executes JavaScript directly. URL encoding the **payload** does not help — the browser decodes the URL before executing the protocol handler.

### `data:` Protocol

```html
<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTs8L3NjcmlwdD4=">test</a>
```

The base64 decodes to:

```html
<script>alert(1);</script>
```

The `data:` URI embeds a complete HTML document inline. The browser renders it, executing the script.

### Why URL Encoding Alone Fails Here

URL encoding protects the **parameter values** within a URL, but it does **not** sanitize the **protocol scheme**. If the attacker controls the entire URL from the beginning, they choose the protocol.

## Defense for `href="$var"`

```java
String safe = ESAPI.encoder().encodeForURL(request.getParameter("input"));
```

But encoding alone is **not sufficient** when the user controls the full URL. You must also:

1. **Whitelist protocols** — only allow `http://` and `https://`
2. **Reject** `javascript:`, `data:`, `vbscript:`, and other dangerous schemes
3. **Validate URL structure** before inserting into the attribute

## Encoding Defense Summary

| Context | ESAPI Method | Protects Against |
|---------|-------------|-----------------|
| HTML body | `encodeForHTML()` | Tag injection |
| HTML attribute | `encodeForHTMLAttribute()` | Attribute breakout |
| JavaScript string | `encodeForJavaScript()` | String breakout, code injection |
| CSS value | `encodeForCSS()` | `expression()`, `@import`, `url()` |
| URL parameter | `encodeForURL()` | Parameter breakout |
| Full URL (`href`) | `encodeForURL()` + **protocol whitelist** | `javascript:`, `data:` schemes |
