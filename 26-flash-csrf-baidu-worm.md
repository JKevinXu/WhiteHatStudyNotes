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

### The Worm Logic

```javascript
var lsURL = window.location.href;
loU = lsURL.split("?");
if (loU.length > 1)
{
  var loallPm = loU[1].split("&");
  ……
```

The worm parsed its own URL parameters to extract configuration (e.g., the current victim's username), then:

1. **Read the victim's friend list** via the JSONP endpoint (`callback=gotfriends`)
2. **Sent a message to every friend** via the mail endpoint (`cm=MailSend`) — the message contained a link to the worm page
3. Each friend who clicked the link became a new victim, repeating the cycle

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
