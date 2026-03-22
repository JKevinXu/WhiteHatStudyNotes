# 32 - CORS, postMessage, and HTML5 Web Storage Security

## Cross-Origin Resource Sharing (CORS)

### The Problem

Same-origin policy blocks XMLHttpRequest from reading cross-origin responses:

```javascript
var client = new XMLHttpRequest();
client.open("GET", "http://www.b.com/test.php");
client.onreadystatechange = function() { }
client.send(null);
```

The browser sends the request, but **blocks JavaScript from reading the response** because `www.b.com` is a different origin.

IE had its own proprietary solution:

```javascript
var request = new XDomainRequest();
request.open("GET", xdomainurl);
request.send();
```

### CORS — The Standard Solution

CORS uses HTTP headers to let servers declare which origins can read their responses.

**Server response header:**

```
Access-Control-Allow-Origin: http://www.a.com
```

Or allow any origin:

```php
<?php
header("Access-Control-Allow-Origin: *");
?>
Cross Domain Request Test!
```

### Full CORS Request/Response Flow

**Request from `www.a.com`:**

```
GET http://www.b.com/test.php HTTP/1.1
Host: www.b.com
Referer: http://www.a.com/test.html
Origin: http://www.a.com
```

The browser automatically adds the `Origin` header to indicate where the request came from.

**Response from `www.b.com`:**

```
HTTP/1.1 200 OK
Server: Apache/2.0.63 (Win32) PHP/5.2.6
Access-Control-Allow-Origin: *
Content-Type: text/html

Cross Domain Request Test!
```

The browser checks: does the `Access-Control-Allow-Origin` header match the requesting origin (or `*`)? If yes, JavaScript can read the response. If no, the browser blocks access.

### CORS Headers — Complete List

**Response headers (server → browser):**

| Header | Purpose |
|--------|---------|
| `Access-Control-Allow-Origin` | Which origins can read the response (`*` or specific origin) |
| `Access-Control-Max-Age` | How long the preflight result can be cached (seconds) |
| `Access-Control-Allow-Credentials` | Whether cookies/auth can be sent (`true` or omit) |
| `Access-Control-Allow-Methods` | Allowed HTTP methods for preflight (`GET, POST, PUT`) |
| `Access-Control-Allow-Headers` | Allowed custom headers for preflight (`X-CSRF-Token`) |

**Request headers (browser → server):**

| Header | Purpose |
|--------|---------|
| `Origin` | The requesting page's origin (added automatically by browser) |
| `Access-Control-Request-Method` | In preflight: which HTTP method will be used |
| `Access-Control-Request-Headers` | In preflight: which custom headers will be sent |

### Security Risk: `Access-Control-Allow-Origin: *`

```
Access-Control-Allow-Origin: *
```

This allows **any website** to read the response. If the endpoint returns sensitive data (user info, tokens, emails), any attacker page can steal it with a simple XHR. Only use `*` for truly public resources.

**With credentials, `*` is not allowed** — the server must echo back the specific origin, which creates a different risk: if the server blindly reflects the `Origin` header, any site can read authenticated responses.

## postMessage — Cross-Origin Communication

### Sending Messages Between Windows/Iframes

```html
<iframe src="http://dev.jquery.com/~john/message/" id="iframe"></iframe>
<form id="form">
  <input type="text" id="msg" value="Message to send"/>
  <input type="submit"/>
</form>
<script>
window.onload = function() {
    var win = document.getElementById("iframe").contentWindow;
    document.getElementById("form").onsubmit = function(e) {
        win.postMessage(document.getElementById("msg").value);
        e.preventDefault();
    };
};
</script>
```

`postMessage` allows safe cross-origin communication between windows.

### What Is postMessage?

`postMessage` is a **browser-level Web API** — part of the HTML5 specification, built into the browser itself. It is **not** a network protocol, not an HTTP feature, and not a JavaScript library. It's a method on the `window` object provided by the browser's DOM API.

**Where it lives in the browser stack:**

```
┌─────────────────────────────────────────┐
│  Your JavaScript code                   │  ← calls window.postMessage()
├─────────────────────────────────────────┤
│  Browser DOM API (window object)        │  ← implements postMessage
│  - window.postMessage()                 │
│  - window.addEventListener("message")   │
├─────────────────────────────────────────┤
│  Browser same-origin policy engine      │  ← enforces origin checks
├─────────────────────────────────────────┤
│  Browser rendering engine               │  ← manages windows, iframes
└─────────────────────────────────────────┘
```

It works entirely **within the browser process** — no HTTP requests are made. The message passes through the browser's internal messaging system from one window/iframe context to another.

### How It Works — Sender and Receiver

**Sender (parent page on `www.a.com`):**

```javascript
var iframe = document.getElementById("myframe");
var targetWindow = iframe.contentWindow;

// Send a message to the iframe, specifying the expected target origin
targetWindow.postMessage("hello from parent", "http://www.b.com");
```

- `targetWindow` — a reference to another window (iframe, popup, or `window.opener`)
- Second argument — the **target origin**; the browser only delivers the message if the target window's origin matches

**Receiver (iframe page on `www.b.com`):**

```javascript
window.addEventListener("message", function(event) {
    // CRITICAL: always check the sender's origin
    if (event.origin !== "http://www.a.com") {
        return;  // reject messages from unexpected origins
    }

    console.log(event.data);    // "hello from parent"
    console.log(event.origin);  // "http://www.a.com"
    console.log(event.source);  // reference to the sender's window
});
```

The `event` object provides:

| Property | Value |
|----------|-------|
| `event.data` | The message content (string, object, array, etc.) |
| `event.origin` | The sender's origin (scheme + host + port) — **set by the browser, cannot be forged** |
| `event.source` | A reference to the sender's window (can reply via `event.source.postMessage(...)`) |

### Why the Browser, Not HTTP?

| | HTTP (CORS, AJAX) | postMessage |
|---|-------------------|-------------|
| **Transport** | Network request to server | In-browser, no network |
| **Who talks** | Client → Server → Client | Client window → Client window |
| **Server involved** | Yes | No |
| **Data format** | HTTP response body | Any JS value (strings, objects, arrays) |
| **Use case** | Fetch data from another origin's server | Communicate between two pages already loaded in the browser |

**Example use cases:**
- A parent page communicating with an embedded third-party widget (iframe)
- A page communicating with a popup it opened via `window.open()`
- An OAuth flow where the popup sends the auth token back to the opener

### Example: OAuth Login via postMessage

When you click "Login with Google" on a website, the site often opens a popup to Google's login page. After authentication, the popup needs to send the token **back to the parent page**. Since the popup is on `accounts.google.com` and the parent is on `myapp.com`, they are cross-origin. `postMessage` bridges this gap.

**The flow:**

```
myapp.com (parent)                    accounts.google.com (popup)
──────────────────                    ─────────────────────────────

1. User clicks "Login with Google"
   var popup = window.open(
     "https://accounts.google.com/oauth?
       redirect_uri=...&client_id=..."
   );
                                      2. User logs in, grants permission

                                      3. Google redirects popup to:
                                         https://myapp.com/callback#token=abc123
                                         (now popup is back on myapp.com origin)

                                      4. Callback page in popup sends token:
                                         window.opener.postMessage(
                                           { token: "abc123" },
                                           "https://myapp.com"
                                         );

5. Parent receives the message:
   window.addEventListener("message",
     function(event) {
       if (event.origin !== "https://myapp.com")
         return;
       var token = event.data.token;
       // Use token to authenticate
     }
   );
                                      6. Popup closes itself:
                                         window.close();
```

**Step-by-step:**

1. **Parent opens popup** — `window.open()` to the OAuth provider (Google). The parent keeps a reference to the popup window.
2. **User authenticates** — enters credentials on Google's page. The parent page waits.
3. **Google redirects the popup** — after auth, Google redirects the popup to `myapp.com/callback` with the token in the URL fragment (`#token=abc123`). The popup is now back on `myapp.com`'s origin.
4. **Popup sends token via postMessage** — the callback page uses `window.opener.postMessage()` to send the token to the parent. `window.opener` is a reference to the window that opened the popup.
5. **Parent receives and validates** — the parent's message handler checks `event.origin` to ensure the message came from a trusted origin, then extracts the token.
6. **Popup closes** — `window.close()`.

**Why postMessage instead of just reading the URL?**
- The parent cannot read the popup's URL once it navigates to a different origin (same-origin policy blocks `popup.location.href`)
- Even after the popup redirects back to `myapp.com`, the parent may not be able to reliably poll for the URL change
- `postMessage` gives explicit, event-driven communication — the popup says "I'm done, here's the token"

**Security considerations:**
- The popup must specify `"https://myapp.com"` as the target origin, not `"*"` — otherwise any page that opened a popup to the same OAuth URL could receive the token
- The parent must verify `event.origin` — otherwise an attacker's popup could send a fake token

**Security risks:**
- The **receiver must check `event.origin`** — without it, any page can send messages and the receiver will trust them (DOM XSS via postMessage)
- The **sender should specify the target origin** as the second argument: `win.postMessage(msg, "http://expected-origin.com")` — using `"*"` means any page loaded in the iframe receives the message

## HTML5 Web Storage

### sessionStorage vs localStorage

```html
<div id="sessionStorage_show">sessionStorage Value:</div>
<div id="localStorage_show">localStorage Value:</div>
<input id="set" type="button" value="check" onclick="set();">

<script>
function set() {
    // Session storage — cleared when tab closes
    window.sessionStorage.setItem("test", "this is sessionStorage");

    // Local storage (modern browsers)
    window.localStorage.setItem("test", "this is LocalStorage");

    // Local storage (old Firefox — globalStorage, deprecated)
    // window.globalStorage.namedItem("a.com").setItem("test", "this is LocalStorage");

    document.getElementById("sessionStorage_show").innerHTML +=
        window.sessionStorage.getItem("test");
    document.getElementById("localStorage_show").innerHTML +=
        window.localStorage.getItem("test");
}
set();
</script>
```

| | `sessionStorage` | `localStorage` |
|---|-----------------|----------------|
| **Lifetime** | Until tab/window closes | Permanent (until explicitly deleted) |
| **Scope** | Per tab, per origin | Per origin (shared across tabs) |
| **Size** | ~5 MB | ~5 MB |
| **Sent with requests** | No | No |

Old Firefox used `globalStorage.namedItem(domain)` — this was replaced by the standard `localStorage` API.

### Web Storage Security Risks

```html
<script>
if (document.domain == "www.a.com") {
    window.localStorage.setItem("test", 123);
}
alert(window.localStorage.getItem("test"));
</script>
```

**Same-origin bound:** Storage is tied to the origin (scheme + host + port). Any script running on that origin can read/write the storage.

**XSS can steal everything:**
- Unlike cookies (which can have `HttpOnly`), there is **no `HttpOnly` equivalent for Web Storage**
- If an attacker achieves XSS, they can read all `localStorage` and `sessionStorage` data with a single line: `JSON.stringify(localStorage)`
- **Never store sensitive tokens in Web Storage** — use HttpOnly cookies for session IDs instead

**localStorage persists forever:**
- Unlike session cookies that expire when the browser closes, `localStorage` data remains until explicitly removed
- Stored credentials, tokens, or personal data remain on the machine indefinitely

## Browser Storage Systems — Complete Picture

Cookies are **not** stored in `localStorage` or `sessionStorage`. The browser maintains several completely separate storage systems:

```
Browser Storage Systems (all separate):
┌─────────────────────────────────────┐
│  Cookie Jar (browser-managed)       │  ← Set-Cookie header / document.cookie
│  - Sent automatically with HTTP     │
│  - HttpOnly hides from JS           │
│  - Scoped by domain + path          │
├─────────────────────────────────────┤
│  localStorage                       │  ← JS-only, never sent with HTTP
├─────────────────────────────────────┤
│  sessionStorage                     │  ← JS-only, per-tab, never sent with HTTP
├─────────────────────────────────────┤
│  IndexedDB                          │  ← JS-only, structured data
├─────────────────────────────────────┤
│  Cache Storage (Service Worker)     │  ← HTTP response caching
└─────────────────────────────────────┘
```

### Why Cookies Are Special

Cookies are the **only** storage that the browser **automatically attaches to every HTTP request** for the matching domain. That's why they're used for session IDs — the server receives them without any JavaScript involvement.

`localStorage` and `sessionStorage` are purely client-side. To send their data to the server, JavaScript must explicitly read the value and add it to the request (e.g., as an `Authorization: Bearer <token>` header).

| | Cookies | localStorage / sessionStorage |
|---|---------|-------------------------------|
| **Set by** | Server (`Set-Cookie` header) or JS (`document.cookie`) | JavaScript only |
| **Sent to server** | Automatically on every matching request | Never (must be added manually by JS) |
| **Accessible by JS** | Yes, unless `HttpOnly` | Always |
| **Size limit** | ~4 KB per cookie | ~5 MB per origin |
| **Scope** | Domain + path | Origin (scheme + host + port) |
| **Expiry** | `Max-Age` / `expires` or session | `localStorage` = permanent, `sessionStorage` = tab close |

### Where Cookies Are Stored on Disk

The browser stores cookies in its own internal database files:

| Browser | Cookie file location (macOS) |
|---------|------------------------------|
| Chrome | `~/Library/Application Support/Google/Chrome/Default/Cookies` (SQLite) |
| Firefox | `~/Library/Application Support/Firefox/Profiles/xxx/cookies.sqlite` (SQLite) |
| Safari | `~/Library/Cookies/Cookies.binarycookies` (binary format) |

These are not plain text files — they're databases managed by the browser. Session cookies (no `expires`) are typically kept only in memory and never written to disk.

### Why They Are Completely Separate — Architecture

Cookies and Web Storage are separate at every level: different browser engine layers, different files on disk, and different behavior in the request pipeline.

**Different browser engine layers:**

```
┌─────────────────────────────────────────────┐
│  JavaScript Runtime Layer                    │
│  ├── localStorage    ← lives here            │
│  ├── sessionStorage  ← lives here            │
│  └── document.cookie ← JS API to read/write  │
│         │              (blocked by HttpOnly)  │
├─────────────────────────────────────────────┤
│  Browser Networking Layer                    │
│  └── Cookie Manager  ← cookies live here     │
│       - Stores all cookies                   │
│       - Attaches them to HTTP requests       │
│       - Enforces HttpOnly, Secure, SameSite  │
└─────────────────────────────────────────────┘
```

Cookies live in the **networking layer** — they're attached to requests before JavaScript even runs. localStorage/sessionStorage live in the **JavaScript runtime layer** — they only exist when JS explicitly accesses them.

**Different files on disk:**

```
Browser internal storage files:
├── Cookies           ← SQLite DB (cookie jar)
├── Local Storage/    ← Separate SQLite DBs or LevelDB
└── Session Storage/  ← Usually memory-only, sometimes temp files
```

**Different roles in the HTTP request pipeline:**

```
Browser makes HTTP request to example.com
        │
        ├── Cookie jar checked automatically
        │   → matching cookies attached to request headers
        │   → Cookie: session_id=abc123
        │
        ├── localStorage — NOT consulted, not involved
        │
        └── sessionStorage — NOT consulted, not involved
```

**This is why `HttpOnly` works and has no Web Storage equivalent:**

`HttpOnly` tells the browser's cookie manager to include the cookie in HTTP requests but **hide it from the JavaScript layer entirely**. The cookie still functions (sent with every request) but JavaScript can't see it via `document.cookie`.

There's no equivalent for localStorage because localStorage **only exists in the JavaScript layer**. If you hid it from JS, there would be nothing left — it's never sent with HTTP requests, so it would be completely inaccessible and useless.
