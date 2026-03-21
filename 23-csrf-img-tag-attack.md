# 23 - CSRF Attack: Forging Requests via Image Tags

## The Vulnerable Action

A blog platform (Sohu) exposes a delete action via a simple GET request:

```
http://blog.sohu.com/manage/entry.do?m=delete&id=156713012
```

No CSRF token, no confirmation — just a URL that deletes a blog post when requested with the user's session cookie.

## The Attack

The attacker hosts a page on their own domain:

```
http://www.a.com/csrf.html
```

The page contains:

```html
<img src="http://blog.sohu.com/manage/entry.do?m=delete&id=156714243" />
```

### How It Works

1. The victim is logged into `blog.sohu.com` (has a valid session cookie)
2. The victim visits `www.a.com/csrf.html` (tricked via link, email, forum post, etc.)
3. The browser renders the `<img>` tag and makes a GET request to the `src` URL
4. The browser **automatically attaches** the victim's `blog.sohu.com` cookies to the request
5. The server receives a valid authenticated request and deletes the blog post
6. The image fails to load (the response isn't an image), but the damage is done

### Why It Works

- **Cookies are sent automatically** — the browser attaches cookies based on the destination domain, regardless of which page initiated the request
- **GET requests have no CSRF protection** — the `<img>` tag makes a cross-origin GET request with no restrictions
- **No user interaction needed** — the request fires as soon as the page loads
- **The attacker never sees the response** — they don't need to; the side effect (deletion) already happened

### Key Differences from XSS

| | XSS | CSRF |
|---|-----|------|
| **Attack target** | The user's browser | The server's trust in the user |
| **Requires vulnerability in** | Target site (injects code) | Target site (no token validation) |
| **Attacker's page** | Not needed (code runs on target) | Hosts the forging payload |
| **Reads data?** | Yes (same-origin) | No (cross-origin, can't read response) |
| **Executes code?** | Yes (JavaScript) | No (just triggers a request) |

### Defenses

- **Never use GET for state-changing operations** — GET should be idempotent (read-only)
- **CSRF tokens** — include a random token in forms that the server validates
- **SameSite cookies** — `SameSite=Strict` or `SameSite=Lax` prevents cookies from being sent on cross-origin requests
- **Referer/Origin header checking** — verify the request originates from your own domain
