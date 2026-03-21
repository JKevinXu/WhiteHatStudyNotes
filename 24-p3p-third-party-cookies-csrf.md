# 24 - P3P Header, Third-Party Cookies, and CSRF via Iframe

## Session vs Persistent Cookies

```php
<?php
header("Set-Cookie: cookie1=123; ");
header("Set-Cookie: cookie2=456; expires=Thu, 01-Jan-2030 00:00:01 GMT; ", false);
?>
```

- **`cookie1`** — no `expires` / `Max-Age`, so it's a **session cookie** (lives only until the browser closes)
- **`cookie2`** — has an `expires` date, so it's a **persistent cookie** (stored on disk, survives browser restart)

## Third-Party Cookie Problem

When an attacker's page embeds the target site in an iframe:

```html
<iframe src="http://www.a.com"></iframe>
```

The browser loads `www.a.com` inside the iframe and must decide: **should it send `www.a.com`'s cookies with the request?**

The cookies belong to `www.a.com` but the request is initiated from a **third-party context** (the parent page is on a different domain). These are called **third-party cookies**.

### Browser Behavior (Historically)

Different browsers handled this differently:

| Browser | Session cookies | Persistent cookies |
|---------|----------------|-------------------|
| IE (default) | **Blocked** in third-party context | **Blocked** in third-party context |
| Firefox (older) | Sent | Sent |
| Chrome (older) | Sent | Sent |

IE was the strictest — it blocked third-party cookies by default, which broke many CSRF attacks but also broke legitimate use cases (SSO, embedded widgets, ad tracking).

### Impact on CSRF

If the browser blocks third-party cookies in iframes:
- The iframe loads `www.a.com` **without** the victim's session cookie
- The server treats it as an unauthenticated request
- The CSRF attack fails

If the browser sends third-party cookies:
- The iframe request carries the victim's session
- The CSRF attack succeeds

## P3P — Platform for Privacy Preferences

To work around IE's cookie blocking, sites could send a **P3P header** declaring their privacy policy:

```
P3P: CP="CURa ADMa DEVa PSAo PSDo OUR BUS UNI PUR INT DEM STA PRE COM NAV OTC NOI DSP COR"
```

When IE saw a valid P3P compact policy, it **allowed third-party cookies** for that domain. This meant:
- Legitimate services (SSO, widgets) could function in iframes on IE
- But attackers could also set P3P headers on their target to ensure cookies were sent in CSRF scenarios

### P3P Is Obsolete

- The W3C deprecated P3P
- Modern browsers ignore P3P headers entirely
- The **SameSite cookie attribute** has replaced this mechanism with clearer, more secure semantics

## Modern Defense: SameSite Cookies

| SameSite Value | Cross-site behavior |
|---------------|-------------------|
| `Strict` | Cookie never sent in cross-site requests |
| `Lax` (default in modern browsers) | Cookie sent only on top-level GET navigations, not iframes/img/form POST |
| `None` | Cookie always sent (requires `Secure` flag) |

`SameSite=Lax` effectively kills both the `<img>` CSRF (note 23) and iframe-based CSRF by default.
