# 15 - Flash XSS: getURL, Embedded SWFs, and clickTAG Injection

## Flash as an XSS Vector

Flash (SWF) files ran inside the browser with access to the embedding page's DOM via `getURL()` and `ExternalInterface`. If an attacker could control parameters passed to a SWF, or host a malicious SWF on the target domain, they could execute JavaScript in that domain's context.

## Attack 1: `getURL("javascript:...")`

The simplest Flash XSS — a SWF that directly calls JavaScript:

```actionscript
getURL("javascript:alert(document.cookie)")
```

`getURL()` with a `javascript:` URI executes the script in the context of the page embedding the SWF. If the SWF is hosted on (or embedded into) the target domain, it has full access to that origin's cookies and DOM.

### Embedding the Malicious SWF

Using `<embed>`:

```html
<embed src="http://yourhost/evil.swf"
  pluginspage="http://www.macromedia.com/shockwave/download/index.cgi?P1_Prod_Version=ShockwaveFlash"
  type="application/x-shockwave-flash"
  width="0"
  height="0"
></embed>
```

`width="0" height="0"` makes the SWF invisible — the victim sees nothing while the script executes.

## Attack 2: XSS via SWF Parameters (`flashvars`)

Many legitimate SWFs accept user-controlled parameters via `flashvars` or URL query strings:

```html
<object classid="clsid:d27cdb6e-ae6d-11cf-96b8-444553540000"
  codebase="http://fpdownload.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=8,0,0,0"
  name="Main" width="1000" height="600" align="middle" id="Main">

  <embed flashvars="site=&sitename="
    src='Loading.swf?user=453156346'
    width="1000" height="600" align="middle" quality="high"
    name="Main" allowscriptaccess="sameDomain"
    type="application/x-shockwave-flash"
    pluginspage="http://www.macromedia.com/go/getflashplayer" />
</object>
```

If the SWF uses parameters like `user`, `site`, or `sitename` in a `getURL()` or `ExternalInterface.call()` without validation, the attacker can inject `javascript:` URIs via the query string or `flashvars`.

### The `allowScriptAccess` Attribute

This attribute controls whether the SWF can call JavaScript:

| Value | Behavior |
|---|---|
| `always` | SWF can call JS regardless of origin — dangerous |
| `sameDomain` | SWF can call JS only if hosted on the same domain as the page |
| `never` | SWF cannot call JS at all |

`sameDomain` is the default, which means a SWF hosted on the target domain can always execute JavaScript. Attackers who can upload a SWF to the target (via file upload, user content, etc.) get code execution.

## Attack 3: clickTAG Injection

### The Pattern

Flash banner ads commonly use a `clickTAG` parameter to set the click-through URL:

```actionscript
on (release) {
  getURL(_root.clickTAG, "_blank");
}
```

The ad network passes the destination URL via the query string:

```
http://example.com/banner.swf?clickTAG=http://advertiser.com/landing
```

### The Exploit

An attacker substitutes a `javascript:` URI:

```
http://example.com/banner.swf?clickTAG=javascript:alert('xss')
```

When the user clicks the banner, `getURL()` executes the JavaScript in the embedding page's context instead of navigating to a URL.

### The (Incomplete) Fix

Some ad developers added protocol validation:

```actionscript
on (release) {
  if (_root.clickTAG.substring(0,5) == "http:" ||
      _root.clickTAG.substring(0,6) == "https:" ||
      _root.clickTAG.substring(0,1) == "/") {
    getURL(_root.clickTAG, "_blank");
  }
}
```

This checks that the URL starts with `http:`, `https:`, or `/` before calling `getURL()`. It blocks `javascript:` URIs but has weaknesses:
- Allows relative paths starting with `/` — could be abused depending on context
- Doesn't check for other dangerous schemes like `data:` or `vbscript:`
- String prefix checks are fragile — case variations (`JavaScript:`) or whitespace (`\njavascript:`) might bypass them depending on the Flash runtime

## Why Flash XSS Was So Prevalent

- SWF files were treated as same-origin content when hosted on the target domain
- Many sites allowed user-uploaded SWF files (avatars, games, ads) without understanding the security implications
- `getURL("javascript:...")` was a direct bridge from Flash to the DOM
- Flash parameters (`flashvars`, query strings) were rarely validated
- Ad networks distributed millions of SWFs with the vulnerable `clickTAG` pattern

## Defenses (Historical Context)

- `allowScriptAccess="never"` for untrusted SWFs
- Validate all Flash parameters against an allowlist of safe URL schemes
- Serve user-uploaded SWFs from a sandboxed domain (different origin)
- Content Security Policy — `object-src 'none'` blocks Flash embeds entirely
- Flash is now dead — all major browsers removed Flash support by end of 2020, eliminating this entire attack class
