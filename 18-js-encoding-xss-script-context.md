# 18 - JavaScript Encoding and XSS in Script Contexts

## Dynamic Script Sources

```html
<script src="$var"></script>
```

If `$var` is user-controlled, an attacker can point it to a malicious script. The browser will fetch and execute whatever URL is injected.

## HTML Entity Encoding Does NOT Help in Script Blocks

### The Problem with `<` in JavaScript

```
1+1<3
```

In an HTML context, the browser may interpret `<3` as the start of a tag. HTML entity encoding (`&lt;`) does **not** work inside `<script>` blocks — the JavaScript engine does not understand HTML entities.

## Backslash Escaping Pitfalls

### Nickname Injection Example

Given a nickname stored as:

```
$nickname = '我是"天才"'
```

A naive backslash escape produces:

```
$nickname = '我是\"天才\"'
```

**In HTML context** — the backslash is rendered literally:

```html
<div>我是\"天才\"</div>
```

**In JavaScript context** — the backslash escapes the quote, but `document.write` outputs the unescaped string:

```html
<script>
var nick = '我是\"天才\"';
document.write(nick);   // outputs: 我是"天才"
</script>
```

### Backslash Escape Bypass

If the application escapes quotes with backslashes but does **not** escape the backslash itself, an attacker can inject `\"` to neutralize the escape:

```javascript
var y = "\"; alert(1); \/\/";
```

The `\"` closes the string, and the payload executes.

### Semicolon / Statement Injection

```javascript
var x = 1; alert(2);
```

If input is placed directly into a numeric assignment without quotes, the attacker simply injects a semicolon and a new statement.

### Hex Encoding Bypass

```javascript
var x = 1\x3balert\x282\x29;
```

- `\x3b` = `;`
- `\x28` = `(`
- `\x29` = `)`

JavaScript interprets hex escape sequences in strings and identifiers, so hex-encoded payloads can bypass naive filters.

## ESAPI JavaScript Encoding — The Safe Approach

OWASP's ESAPI `JavaScriptCodec` avoids character escape shortcuts (`\"`, `\'`, `\\`) because they can break out of HTML attribute contexts:

```java
public String encodeCharacter(char[] immune, Character c) {

    // Immune characters pass through
    if (containsCharacter(c, immune)) {
        return "" + c;
    }

    // Alphanumerics pass through
    String hex = Codec.getHexForNonAlphanumeric(c);
    if (hex == null) {
        return "" + c;
    }

    // NEVER use shortcut escapes like \" \' \\
    // They can break out of HTML attributes like onmouseover="..."

    // Encode ASCII (< 256) as \xHH
    String temp = Integer.toHexString(c);
    if (c < 256) {
        String pad = "00".substring(temp.length());
        return "\\x" + pad + temp.toUpperCase();
    }

    // Encode non-ASCII as \uHHHH
    String pad = "0000".substring(temp.length());
    return "\\u" + pad + temp.toUpperCase();
}
```

### Why Not Use `\"` or `\'`?

Consider an HTML attribute like:

```html
<div onmouseover="var x='USER_INPUT'">
```

If `USER_INPUT` is `'; alert(1); //` and the app escapes to `\'; alert(1); //`:

- The `\'` keeps the JS string open, **but** the `'` still closes the HTML attribute
- The attacker breaks out of the attribute and can inject new event handlers

Using `\x27` (for `'`) or `\x22` (for `"`) instead is safe in **both** JS and HTML attribute contexts, because neither character appears literally in the output.

### Encoding Summary

| Character | Unsafe Escape | Safe Escape |
|-----------|--------------|-------------|
| `"`       | `\"`         | `\x22`      |
| `'`       | `\'`         | `\x27`      |
| `\`       | `\\`         | `\x5C`      |
| `;`       | n/a          | `\x3B`      |
| All other non-alphanumeric | varies | `\xHH` or `\uHHHH` |
