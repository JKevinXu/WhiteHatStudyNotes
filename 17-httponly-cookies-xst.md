# 17 - HttpOnly Cookies and Cross-Site Tracing (XST)

## HttpOnly Cookie Flag

### Set-Cookie Syntax

```
Set-Cookie: <name>=<value>[; Max-Age=<age>]
  [; expires=<date>][; domain=<domain_name>]
  [; path=<some_path>][; secure][; HttpOnly]
```

The `HttpOnly` flag tells the browser to prevent JavaScript from accessing the cookie via `document.cookie`. This is a defense against XSS-based cookie theft.

### PHP Example

```php
<?php
header("Set-Cookie: cookie1=test1; ");
header("Set-Cookie: cookie2=test2; httponly", false);
?>

<script>
  alert(document.cookie);
</script>
```

- `cookie1` has **no** HttpOnly flag — it appears in `document.cookie` and the alert displays it
- `cookie2` has the `httponly` flag — the browser hides it from JavaScript
- The `false` parameter in PHP's `header()` prevents replacing the previous Set-Cookie header (allows multiple cookies)

### Java Example

```java
response.setHeader("Set-Cookie",
    "cookiename=value; Path=/; Domain=domainvalue; Max-Age=seconds; HTTPOnly");
```

## Cross-Site Tracing (XST) — Bypassing HttpOnly

### The TRACE HTTP Method

The `TRACE` method is a diagnostic tool defined in HTTP/1.1. The server echoes the **entire request** back in the response body, including all headers.

```
$ telnet foo.com 80
TRACE / HTTP/1.1
Host: foo.bar
X-Header: test

HTTP/1.1 200 OK
Date: Mon, 02 Dec 2002 19:24:51 GMT
Server: Apache/2.0.40 (Unix)
Content-Type: message/http

TRACE / HTTP/1.1
Host: foo.bar
X-Header: test
```

### The Attack

When a browser sends a request, it automatically attaches cookies — including HttpOnly cookies. If an attacker can issue a `TRACE` request via JavaScript (e.g., using `XMLHttpRequest`), the server reflects the full request back, **including the HttpOnly cookies** in the response body. The attacker can then read the response and extract the cookies.

**Attack flow:**
1. Victim has an HttpOnly session cookie for `target.com`
2. XSS payload on the page sends a TRACE request to `target.com`
3. Browser attaches the HttpOnly cookie to the request automatically
4. Server echoes everything back in the response body (plain text)
5. JavaScript reads the response body and extracts the cookie value

### Why It Worked

- `document.cookie` correctly hides HttpOnly cookies
- But the TRACE response body is just text — not subject to the HttpOnly restriction
- The cookie appears in the reflected request headers, readable by script

### Mitigations

- **Disable TRACE** on the server (most servers now disable it by default)
- Modern browsers **block TRACE via XMLHttpRequest** — `xhr.open("TRACE", ...)` is denied
- The combination of server-side and browser-side defenses has effectively killed this attack vector
