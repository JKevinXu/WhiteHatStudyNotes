# 19 - Context-Specific Output Encoding and XSS Injection Points

## Server-Side Encoding Libraries

### Apache Commons Lang — StringEscapeUtils

```java
import org.apache.commons.lang.StringEscapeUtils;

StringEscapeUtils.escapeJava(str);        // Java string escaping
StringEscapeUtils.escapeJavaScript(str);  // JavaScript string escaping
StringEscapeUtils.escapeSql(str);         // SQL escaping (basic)
StringEscapeUtils.escapeXml(str);         // XML entity escaping
StringEscapeUtils.escapeHtml(str);        // HTML entity escaping
```

### Template Engines (e.g., Django/Jinja2)

```
{{ var|escape }}
```

Applies context-aware HTML escaping. But this only handles the **HTML context** — it does NOT protect against injection in JavaScript, URL, or CSS contexts.

## The Wrong-Context Encoding Problem

### HTML Encoding Inside a JavaScript Context

Given:

```html
<a href=# onclick="alert('$var')">test</a>
```

If `$var` is `'); alert('2` and the app applies **HTML encoding**:

```
$var = htmlencode("'); alert('2");
// Result: &#x27;&#x29;&#x3b; alert&#x28;&#x27;2
```

The HTML becomes:

```html
<a href=# onclick="alert('&#x27; &#x29; &#x3b; alert&#x28; &#x27;2')">test</a>
```

This looks safe in the source. **But the browser decodes HTML entities before passing the value to the JavaScript engine**, so the JS engine actually sees:

```html
<a href=# onclick="alert(''); alert('2')">test</a>
```

The injection succeeds. **HTML encoding does not protect JavaScript contexts inside HTML attributes.**

## XSS Injection Points by Context

### 1. HTML Body Context

```html
<div>$var</div>
<a href=#>$var</a>
```

**Attack:** Inject HTML tags directly:

```html
<a href=#><img src=# onerror=alert(1) /></a>
```

**Defense:** HTML entity encoding (`&lt;`, `&gt;`, `&amp;`, `&quot;`)

### 2. HTML Attribute Context

```html
<div id="abc" name="$var"></div>
```

**Attack:** Close the attribute and inject new elements:

```html
<div id="abc" name=""><script>alert(/xss/)</script><""></div>
```

**Defense:** ESAPI attribute encoding:

```java
String safe = ESAPI.encoder().encodeForHTMLAttribute(request.getParameter("input"));
```

### 3. JavaScript Variable Context

```html
<script>
var x = "$var";
</script>
```

**Attack:** Close the string and inject code:

```html
<script>
var x = ""; alert(/xss/); //";
</script>
```

**Defense:** JavaScript hex encoding (`\xHH` / `\uHHHH`) — NOT HTML encoding, NOT backslash escaping

### 4. JavaScript Inside HTML Attribute (Double Context)

```html
<a href=# onclick="funcA('$var')">test</a>
```

**Attack:**

```html
<a href=# onclick="funcA(''); alert(/xss/); //')">test</a>
```

**Defense:** Must apply **JavaScript encoding first, then HTML encoding** — two layers for two contexts. The browser decodes HTML entities first, then passes the result to the JS engine.

### 5. CSS Context

```html
<STYLE>@import 'http://ha.ckers.org/xss.css';</STYLE>

<STYLE>BODY{-moz-binding:url("http://ha.ckers.org/xssmoz.xml#xss")}</STYLE>

<XSS STYLE="behavior: url(xss.htc);">

<STYLE>li {list-style-image: url("javascript:alert('XSS')");}</STYLE>

<DIV STYLE="background-image: url(javascript:alert('XSS'))">

<DIV STYLE="width: expression(alert('XSS'));">
```

CSS injection vectors include:
- **`@import`** — loads external stylesheets that can contain malicious rules
- **`-moz-binding`** — Firefox-specific, binds XML behavior to elements
- **`behavior`** — IE-specific, loads HTC component files
- **`expression()`** — IE-specific, executes JavaScript inside CSS
- **`javascript:` URLs** — in `url()` values in older browsers

**Defense:** CSS hex encoding or strict whitelisting. Never allow user input in style blocks or attributes.

## Encoding Summary by Context

| Output Context | Encoding Method | Example |
|---------------|----------------|---------|
| HTML body | HTML entity encode | `&lt;` `&gt;` `&amp;` |
| HTML attribute | HTML attribute encode | `&#x22;` `&#x27;` |
| JavaScript string | JS hex encode | `\x22` `\x27` `\x3B` |
| JS in HTML attribute | JS encode → then HTML encode | Two layers |
| CSS value | CSS hex encode | `\22` `\27` |
| URL parameter | URL percent encode | `%22` `%27` |

**The cardinal rule: always encode for the correct output context. HTML encoding does not protect JavaScript contexts, and vice versa.**
