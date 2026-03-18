# 04 - DOM-Based XSS via innerHTML

## Vulnerable Code

```html
<script>
function test(){
  var str = document.getElementById("text").value;
  document.getElementById("t").innerHTML = "<a href='" + str + "' >testLink</a>";
}
</script>

<div id="t"></div>
<input type="text" id="text" value="" />
<input type="button" id="s" value="write" onclick="test()" />
```

User input is directly concatenated into HTML via `innerHTML` — classic DOM-based XSS.

## Attack 1: Event Handler Injection

Input:

```
' onclick=alert(/xss/) //
```

Result:

```html
<a href='' onclick=alert(/xss/)//' >testLink</a>
```

The single quote closes the `href` attribute, then `onclick` is injected as a new attribute. The `//` comments out the trailing quote. Clicking the link fires `alert(/xss/)`.

## Attack 2: Tag Injection via `<img onerror>`

Input:

```
'><img src=# onerror=alert(/xss2/) /><'
```

Result:

```html
<a href=''><img src=# onerror=alert(/xss2/) /><'' >testLink</a>
```

The `'>` closes both the `href` attribute and the `<a>` tag. Then a new `<img>` tag is injected. Since `src=#` fails to load, `onerror` fires immediately — no user interaction needed. This is more dangerous than Attack 1 because it executes automatically.

## Why `innerHTML` Is Dangerous

- The browser parses the assigned string as full HTML, including new tags and event handlers
- User input becomes part of the DOM structure, not just text content
- Any attribute or tag can be injected by breaking out of the current context

## Fix

```javascript
function test(){
  var str = document.getElementById("text").value;
  var a = document.createElement("a");
  a.href = str;
  a.textContent = "testLink";
  var t = document.getElementById("t");
  t.textContent = "";
  t.appendChild(a);
}
```

Using `createElement` + `textContent` instead of `innerHTML` ensures user input is never parsed as HTML. The browser treats `str` as a plain string value for the `href` attribute.

Note: this still allows `javascript:alert(1)` as an href. To fully protect, also validate that the URL starts with `http://` or `https://`.
