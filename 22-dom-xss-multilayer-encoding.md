# 22 - DOM-Based XSS and Multi-Layer Encoding Challenges

## DOM XSS via innerHTML

### Vulnerable Pattern

```html
<script>
function test() {
  var str = document.getElementById("text").value;
  document.getElementById("t").innerHTML = "<a href='" + str + "'>testLink</a>";
}
</script>

<div id="t"></div>
<input type="text" id="text" value="" />
<input type="button" id="s" value="write" onclick="test()" />
```

The dangerous line:

```javascript
document.getElementById("t").innerHTML = "<a href='" + str + "'>testLink</a>";
```

User input goes directly into `innerHTML`, which the browser parses as HTML. The attacker can inject any HTML/JS payload by closing the `href` attribute.

## Server-Side Variable into document.write — Hex Escape Bypass

### The Setup

Server renders a variable into JavaScript:

```html
<script>
var x = "$var";
document.write("<a href='" + x + "'>test</a>");
</script>
```

### The Attack

The server applies JavaScript encoding (hex escapes) to `$var`:

```html
<script>
var x = "\x20\x27onclick\x3dalert\x281\x29\x3b\x2f\x2f\x27";
document.write("<a href='" + x + "'>test</a>");
</script>
```

At the `var x = "..."` level, the hex escapes are valid JavaScript string encoding. The JS engine decodes them:

```
x = " 'onclick=alert(1);//'"
```

Then `document.write` outputs:

```html
<a href=' 'onclick=alert(1);//''>test</a>
```

The `'` closes the `href`, and `onclick=alert(1)` becomes a new event handler. **JavaScript encoding protected the JS string context, but `document.write` passes the decoded value into a new HTML context — creating a second-order injection.**

## The document.write Multi-Context Problem

### Triple Context: JS Variable → document.write → HTML Attribute → JavaScript Event

```html
<script>
var x = "1&#x22; &#x29; &#x3b; alert&#x28;2&#x29; &#x3b; &#x2f; &#x2f; &#x22; ";
document.write("<a href=# onclick='alert(\"" + x + "\")'>test</a>");
</script>
```

**Step-by-step decoding:**

**Step 1 — JavaScript engine** parses `var x = "..."`. The string contains HTML entities (`&#x22;`, `&#x3b;`, etc.). The JS engine does NOT decode HTML entities — they remain as literal text.

```
x = "1&#x22; &#x29; &#x3b; alert&#x28;2&#x29; &#x3b; &#x2f; &#x2f; &#x22; "
```

**Step 2 — document.write** outputs the HTML string to the DOM:

```html
<a href=# onclick='alert("1&#x22; &#x29; &#x3b; alert&#x28;2&#x29; &#x3b; &#x2f; &#x2f; &#x22; ")'>test</a>
```

**Step 3 — HTML parser** processes the element and decodes HTML entities in the `onclick` attribute:

```
&#x22; → "
&#x28; → (
&#x29; → )
&#x3b; → ;
&#x2f; → /
```

So the `onclick` handler becomes:

```javascript
alert("1" ) ; alert(2) ; / / " ")
```

**Step 4 — JavaScript engine** executes the decoded `onclick` value — `alert(2)` fires.

### Why This Is Hard to Defend

The value passes through **three contexts** in sequence:

```
JS string → document.write → HTML parser → JS event handler
     ①              ②              ③              ④
```

- Encoding for context ① (JS) doesn't protect against context ③ (HTML decode)
- HTML entities survive JS string parsing unchanged, then get decoded by the HTML parser
- The decoded result becomes executable JS in the event handler

### Defense

- **Avoid `document.write` and `innerHTML`** — use safe DOM APIs like `textContent`, `setAttribute`, or `createElement`
- If you must build HTML dynamically, apply encoding at **each context transition**
- Use Content Security Policy (CSP) to block inline event handlers
