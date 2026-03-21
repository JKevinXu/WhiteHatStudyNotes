# 21 - Rich Text XSS and HTML Sanitization with AntiSamy

## The Problem: Rich Text Input

Some features require users to submit HTML (e.g., blog posts, forum comments, email editors). You cannot simply encode all HTML — that would destroy the formatting. But allowing raw HTML opens the door to XSS.

**Challenge:** Allow safe HTML tags (`<b>`, `<i>`, `<p>`, `<img>`) while blocking dangerous ones (`<script>`, `<iframe>`, event handlers).

## AntiSamy — Whitelist-Based HTML Sanitization

OWASP AntiSamy takes a whitelist approach: define a **policy** of allowed tags, attributes, and CSS properties, then sanitize input against it.

```java
import org.owasp.validator.html.*;

Policy policy = Policy.getInstance(POLICY_FILE_LOCATION);
AntiSamy as = new AntiSamy();
CleanResults cr = as.scan(dirtyInput, policy);
MyUserDAO.storeUserProfile(cr.getCleanHTML());
```

### How It Works

1. **Load a policy file** — an XML file defining which HTML tags, attributes, and CSS properties are allowed
2. **Scan the input** — AntiSamy parses the HTML and checks every element against the policy
3. **Get clean output** — `getCleanHTML()` returns sanitized HTML with all disallowed elements removed or neutralized
4. **Store the safe HTML** — the cleaned output can be safely rendered in the browser

### Policy File

The policy file is the core of AntiSamy. It defines:
- **Allowed tags** — e.g., `<b>`, `<i>`, `<p>`, `<ul>`, `<li>`, `<img>`
- **Allowed attributes per tag** — e.g., `<img>` may have `src`, `alt`, `width`, but not `onerror`
- **Allowed CSS properties** — e.g., `color`, `font-size`, but not `expression()` or `-moz-binding`
- **Allowed URL protocols** — e.g., `http`, `https`, but not `javascript` or `data`

OWASP provides several preset policies ranging from strict (minimal tags) to permissive (most formatting allowed).

### Why Whitelist, Not Blacklist

- **Blacklisting** tries to block known-bad input (`<script>`, `onclick`, etc.) — attackers constantly find new bypasses with encoding tricks, browser quirks, and new HTML features
- **Whitelisting** only allows known-safe elements — anything not explicitly permitted is removed, making it resilient against unknown attack vectors

### Key Principle

**Input validation (sanitization) on write, output encoding on read.** AntiSamy sanitizes HTML before storing it. When displaying, the stored HTML is already clean and can be rendered as-is.
