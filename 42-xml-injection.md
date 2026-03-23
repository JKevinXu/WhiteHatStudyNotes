# 42 - XML Injection and Defense

## What Is XML Injection?

XML injection occurs when user input is concatenated directly into an XML document, allowing the attacker to modify the XML structure — similar to SQL injection but targeting XML data instead of SQL queries.

## The Vulnerable Code

```java
final String GUESTROLE = "guest_role";

// userdata is XML to be saved; receives 'name' and 'email' from user input
String userdata = "<USER role=" +
              GUESTROLE +
              "><name>" +
              request.getParameter("name") +
              "</name><email>" +
              request.getParameter("email") +
              "</email></USER>";

// Save the XML data
userDao.save(userdata);
```

User input (`name`, `email`) is concatenated directly into the XML string without any escaping or validation.

### Normal Input

```
name = "user1"
email = "user1@a.com"
```

Produces valid XML:

```xml
<USER role="guest_role">
    <name>user1</name>
    <email>user1@a.com</email>
</USER>
```

### Malicious Input — Privilege Escalation

The attacker submits:

```
email = user1@a.com</email></USER><USER role="admin_role"><name>test</name><email>user2@a.com
```

The resulting XML:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<USER role="guest_role">
    <name>user1</name>
    <email>user1@a.com</email>
</USER>
<USER role="admin_role">
    <name>test</name>
    <email>user2@a.com</email>
</USER>
```

### What Happened

```
Original XML structure:          After injection:
┌──────────────────────┐         ┌──────────────────────┐
│ USER role=guest_role │         │ USER role=guest_role │ ← original, closed early
│   name: user1        │         │   name: user1        │
│   email: user1@a.com │         │   email: user1@a.com │
└──────────────────────┘         ├──────────────────────┤
                                 │ USER role=admin_role │ ← injected by attacker!
                                 │   name: test         │
                                 │   email: user2@a.com │
                                 └──────────────────────┘
```

The attacker:
1. **Closed the `<email>` tag** with `</email>`
2. **Closed the `<USER>` tag** with `</USER>`
3. **Opened a new `<USER>` tag** with `role="admin_role"` — escalating from guest to admin
4. **Added valid child elements** to make the XML well-formed

If the application processes this XML and creates user accounts, the attacker now has an admin account.

## The Injection Pattern

This follows the same pattern as SQL injection and XSS:

| Attack Type | What's injected into | Closes with | Injects |
|-------------|---------------------|-------------|---------|
| SQL Injection | SQL query string | `'` or `"` | New SQL statements |
| XSS | HTML document | `">` or `</script>` | New HTML/JS |
| XML Injection | XML document | `</tag>` | New XML elements |

The root cause is always the same: **untrusted data is mixed with structural syntax without separation**.

## Defense: XML Entity Encoding

### The 5 XML Special Characters

XML defines 5 characters that have structural meaning and must be encoded when used as data:

```java
static {
    entityToCharacterMap = new HashTrie<Character>();
    entityToCharacterMap.put("lt",   '<');    // &lt;
    entityToCharacterMap.put("gt",   '>');    // &gt;
    entityToCharacterMap.put("amp",  '&');    // &amp;
    entityToCharacterMap.put("apos", '\'');   // &apos;
    entityToCharacterMap.put("quot", '"');    // &quot;
}
```

| Character | Entity | Why it's dangerous |
|-----------|--------|-------------------|
| `<` | `&lt;` | Opens new XML tags |
| `>` | `&gt;` | Closes XML tags |
| `&` | `&amp;` | Starts entity references |
| `'` | `&apos;` | Closes single-quoted attribute values |
| `"` | `&quot;` | Closes double-quoted attribute values |

### Applying the Defense

With proper encoding, the attacker's input:

```
user1@a.com</email></USER><USER role="admin_role">
```

Becomes:

```
user1@a.com&lt;/email&gt;&lt;/USER&gt;&lt;USER role=&quot;admin_role&quot;&gt;
```

The `<`, `>`, and `"` are encoded as entities. The XML parser treats them as literal text, not structural elements. The injection fails.

### Best Practices

| Defense | How |
|---------|-----|
| **XML entity encoding** | Encode all 5 special characters in user input before inserting into XML |
| **Use XML libraries** | Build XML with DOM APIs (`createElement`, `setTextContent`) instead of string concatenation — the library handles encoding automatically |
| **Input validation** | Validate that email looks like an email, name contains only expected characters |
| **Schema validation** | Validate the final XML against an XSD schema — rejects unexpected elements |
