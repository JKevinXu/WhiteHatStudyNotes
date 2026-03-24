# 45 - Session Management and Access Control

## Password Storage — Salted Hashing

```
MD5(Username + Password + Salt)
```

Passwords should never be stored in plain text. A salted hash combines:
- **Username** — makes the hash unique per user (even if two users have the same password)
- **Password** — the secret
- **Salt** — a random value stored alongside the hash, prevents rainbow table attacks

**Note:** MD5 is considered weak for password hashing. Modern best practice uses bcrypt, scrypt, or Argon2, which are intentionally slow to resist brute-force attacks.

## Session ID Security

### Session ID in URL — Bad Practice

```
http://bbs.xxxx.com/wap/index.php?action=forum&fid=72&sid=2iu2pf
```

The session ID (`sid=2iu2pf`) is in the URL. This is dangerous because:

| Leak vector | How the session ID escapes |
|-------------|--------------------------|
| **Referer header** | Any link clicked on this page sends the full URL (including `sid`) to the next site |
| **Browser history** | The session ID is stored in browsing history |
| **Server logs** | Access logs record the full URL |
| **Shared URLs** | User copies the URL to share — session goes with it |
| **Shoulder surfing** | Session ID visible in the address bar |

**Session IDs should always be in cookies**, not URLs. Cookies with `HttpOnly` and `Secure` flags are not exposed via Referer headers, history, or logs.

## Session Fixation — Keeping a Cookie Alive Forever

An attacker who steals a session cookie wants to keep it valid indefinitely:

```javascript
// Make a cookie never expire
anehta.dom.persistCookie = function(cookieName) {
    if (anehta.dom.checkCookie(cookieName) == false) {
        return false;
    }

    try {
        document.cookie = cookieName + "=" +
            anehta.dom.getCookie(cookieName) +
            "; expires=Thu, 01-Jan-2038 00:00:01 GMT;";
    } catch (e) {
        return false;
    }
    return true;
}
```

This XSS payload (from the Anehta framework) reads an existing cookie and rewrites it with an expiration date far in the future (2038). Even if the original cookie was a session cookie (expires when browser closes), the attacker's version persists on disk.

**Why this matters:**
- The victim closes their browser thinking the session ended
- The attacker's copy of the cookie remains valid
- The server never invalidated the session — it's still active
- The attacker can use the session days or weeks later

**Defense:** Server-side session expiration. The server should:
- Set a maximum session lifetime (e.g., 24 hours)
- Invalidate sessions on logout (delete from server-side session store)
- Regenerate session IDs after authentication
- Never rely solely on cookie expiration for security

## Access Control — URL-Based Permission Check

### Java Servlet Filter Pattern

```java
// Get the requested URL path
String url = request.getRequestPath();

// Perform permission check
User user = request.getSession().get("user");
boolean permit = PrivilegeManager.permit(user, url);

if (permit) {
    chain.doFilter(request, response);
} else {
    // Redirect to access denied page
}
```

### How It Works

```
User Request
  → Servlet Filter intercepts
    → Extract URL path (e.g., "/admin/deleteUser")
    → Get user from session
    → PrivilegeManager checks: does this user have access to this URL?
      → Yes: chain.doFilter() — pass request to the actual handler
      → No: redirect to "access denied" page
```

This is a **centralized access control** pattern — all requests pass through a single filter that checks permissions before any business logic executes.

### Common Access Control Mistakes

| Mistake | Why it's dangerous |
|---------|-------------------|
| **Client-side only** | Hiding buttons/links doesn't prevent direct URL access |
| **Checking only the first page** | Attacker can skip to step 3 of a multi-step process |
| **Role check in each handler** | Easy to forget one handler — inconsistent enforcement |
| **Trusting user-supplied role** | `?role=admin` in the request — server must check, not trust |
| **Vertical privilege only** | Checking admin vs user but not user A vs user B (horizontal privilege) |

### Vertical vs Horizontal Privilege Escalation

```
Vertical:   regular user → admin      (accessing higher privilege functions)
Horizontal: user A → user B's data    (accessing another user's resources)
```

**Vertical example:** A normal user accesses `/admin/deleteUser` — the filter should block this.

**Horizontal example:** User A accesses `/profile?id=123` (User B's profile) — the filter checks that User A has access to `/profile`, which is allowed. But it doesn't check that `id=123` belongs to User A. This requires **object-level authorization**, not just URL-level.

### Defense: Layered Access Control

| Layer | What it checks |
|-------|---------------|
| **URL filter** | Does this role have access to this URL path? |
| **Method-level** | Does this user have permission for this action (read/write/delete)? |
| **Object-level** | Does this user own or have access to this specific resource? |
