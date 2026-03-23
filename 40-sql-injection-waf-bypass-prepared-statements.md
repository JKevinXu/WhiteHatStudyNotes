# 40 - SQL Injection: WAF Bypass, Filter Evasion, and Parameterized Queries

## When mysql_real_escape_string Isn't Enough

```php
$sql = "SELECT id, name, mail, cv, blog, twitter FROM register WHERE
  id=".mysql_real_escape_string($_GET['id']);
```

`mysql_real_escape_string()` escapes quotes and special characters. But here, the `id` parameter is **numeric** — it's concatenated directly without quotes. The attacker doesn't need quotes at all:

```
http://vuln.example.com/user.php?id=12,AND,1=0,union,select,1,
  concat(user,0x3a,password),3,4,5,6,from,mysql.user,
  where,user=substring_index(current_user(),char(64),1)
```

No quotes in the payload — `mysql_real_escape_string()` has nothing to escape. The injection succeeds because the value was never quoted in the SQL string in the first place.

**Lesson:** Escaping only protects **string contexts** (inside quotes). For numeric parameters, always cast to integer or use parameterized queries.

## SQL Injection Filter Evasion

### Bypassing Space Filters

If a WAF blocks spaces in SQL, attackers use alternatives:

**SQL comments as whitespace:**

```sql
SELECT/**/passwd/**/from/**/user
```

`/**/` (empty comment) acts as a word separator in SQL. The parser ignores the comment and sees: `SELECT passwd from user`.

**Parentheses as separators:**

```sql
SELECT(passwd)from(user)
```

Parentheses around column names and table names serve as implicit separators — no spaces needed.

### Bypassing Quote Filters

If quotes are filtered, use hex encoding for string values:

```sql
SELECT passwd from users where user=0x61646D696E
```

`0x61646D696E` is the hex encoding of `'admin'`. MySQL accepts hex literals as string values — no quotes required.

**Common hex conversions:**

| String | Hex |
|--------|-----|
| `admin` | `0x61646D696E` |
| `root` | `0x726F6F74` |
| `password` | `0x70617373776F7264` |

### Other Evasion Techniques

| Technique | Example | Bypasses |
|-----------|---------|----------|
| Comments as spaces | `SELECT/**/passwd/**/FROM/**/users` | Space filters |
| Parentheses | `SELECT(passwd)FROM(user)` | Space filters |
| Hex strings | `WHERE user=0x61646D696E` | Quote filters |
| `CHAR()` function | `WHERE user=CHAR(97,100,109,105,110)` | Quote filters |
| Commas as spaces | `id=12,AND,1=0,union,select,1` | Some WAF patterns |
| Case variation | `SeLeCt`, `uNiOn` | Case-sensitive filters |
| URL encoding | `%53%45%4C%45%43%54` | Application-level filters |
| Double URL encoding | `%2553%2545%254C` | Filters that decode once |
| Inline comments | `UN/**/ION SE/**/LECT` | Keyword-matching filters |

## The Real Defense: Parameterized Queries (Prepared Statements)

Parameterized queries are the **only reliable defense** against SQL injection. They separate SQL structure from data at the protocol level — no escaping needed, no encoding tricks possible.

### Java — PreparedStatement

```java
String custname = request.getParameter("customerName");
// Input validation should ALSO be performed

String query = "SELECT account_balance FROM user_data WHERE user_name = ?";

PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, custname);
ResultSet results = pstmt.executeQuery();
```

### PHP — MySQLi with bind_param

```php
$query = "INSERT INTO myCity (Name, CountryCode, District) VALUES (?, ?, ?)";
$stmt = $mysqli->prepare($query);
$stmt->bind_param("sss", $val1, $val2, $val3);
$val1 = 'Stuttgart';
$val2 = 'DEU';
$val3 = 'Baden-Wuerttemberg';
$stmt->execute();
```

The `"sss"` type string means all three parameters are strings. Other types: `i` (integer), `d` (double), `b` (blob).

### How Parameterized Queries Work Internally

```
WITHOUT parameterized queries:
┌─────────────────────────────────────────────────────────────┐
│ App builds SQL string: "SELECT * FROM users WHERE id=" + input │
│ Sends to DB: "SELECT * FROM users WHERE id=1; DROP TABLE users" │
│ DB parses: finds TWO statements → executes both                │
└─────────────────────────────────────────────────────────────┘

WITH parameterized queries:
┌─────────────────────────────────────────────────────────────┐
│ Step 1: App sends SQL template:                              │
│         "SELECT * FROM users WHERE id = ?"                   │
│         DB compiles and stores the query plan                │
│                                                              │
│ Step 2: App sends parameter value separately:                │
│         Parameter 1 = "1; DROP TABLE users"                  │
│         DB treats this ENTIRE string as a data value         │
│         It can NEVER become SQL syntax                       │
│                                                              │
│ Result: SELECT * FROM users WHERE id = '1; DROP TABLE users' │
│         (searches for a literal string, finds nothing)       │
└─────────────────────────────────────────────────────────────┘
```

The query structure is compiled **before** the data is inserted. The data can never alter the SQL syntax because the parser has already finished.

### Parameterized Queries by Language/Framework

| Language/Framework | API |
|-------------------|-----|
| **Java EE** | `PreparedStatement()` with bind variables |
| **.NET** | `SqlCommand()` or `OleDbCommand()` with bind variables |
| **PHP** | PDO with `bindParam()` (strongly typed) |
| **Hibernate** | `createQuery()` with named parameters |
| **SQLite** | `sqlite3_prepare()` statement objects |
| **Python** | `cursor.execute(query, params)` with `%s` or `?` placeholders |
| **Node.js** | `connection.query(sql, [params])` with `?` placeholders |

### Defense in Depth

| Layer | Defense | Purpose |
|-------|---------|---------|
| **Primary** | Parameterized queries | Prevents SQL injection entirely |
| **Secondary** | Input validation (whitelist) | Reject obviously malicious input early |
| **Tertiary** | Least privilege DB user | Limits damage if injection occurs (no FILE, no CREATE FUNCTION) |
| **Monitoring** | WAF + logging | Detect and alert on attack attempts |

**Parameterized queries are the only defense that cannot be bypassed.** Escaping, encoding, WAFs, and filters can all be evaded. Prepared statements cannot — the data is structurally separated from the SQL.
