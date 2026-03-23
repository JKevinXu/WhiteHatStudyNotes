# 41 - SQL Injection Defense: Type Casting, Escaping, and ESAPI Encoding

## Type Casting for Numeric Parameters

When the parameter is numeric, the simplest defense is to enforce the type:

### PHP — settype() and sprintf()

```php
<?php
// Method 1: Cast to integer — any non-numeric input becomes 0
settype($offset, 'integer');
$query = "SELECT id, name FROM products ORDER BY name LIMIT 20 OFFSET $offset;";

// Method 2: sprintf with %d — forces integer formatting
$query = sprintf("SELECT id, name FROM products ORDER BY name LIMIT 20 OFFSET %d;",
                  $offset);
?>
```

**Why `%d` and not `%s`:**

| Format | Input: `"1; DROP TABLE products"` | Result |
|--------|----------------------------------|--------|
| `%s` (string) | `OFFSET 1; DROP TABLE products` | Injection succeeds |
| `%d` (integer) | `OFFSET 1` | PHP converts to int, drops everything after the number |

`%d` forces the value to an integer. Any trailing SQL injection payload is discarded during the type conversion. This is safe for numeric parameters but **cannot be used for string parameters**.

## MySQL Escaping — Character Reference

`mysql_real_escape_string()` and similar functions escape these characters:

```
NUL (0x00) --> \0    [null byte — can truncate strings in C-based parsers]
BS  (0x08) --> \b    [backspace]
TAB (0x09) --> \t    [tab]
LF  (0x0a) --> \n    [newline — can break out of single-line contexts]
CR  (0x0d) --> \r    [carriage return]
SUB (0x1a) --> \z    [substitute — EOF marker in Windows]
"   (0x22) --> \"    [double quote — closes double-quoted strings]
%   (0x25) --> \%    [percent — LIKE wildcard]
'   (0x27) --> \'    [single quote — closes single-quoted strings]
\   (0x5c) --> \\    [backslash — escape character itself]
_   (0x5f) --> \_    [underscore — LIKE single-char wildcard]

All other non-alphanumeric chars with ASCII < 256 --> \c
(where 'c' is the original character)
```

### Why Each Character Matters

| Character | Risk if unescaped |
|-----------|------------------|
| `'` and `"` | Close string literals — the primary injection vector |
| `\` | Could escape the escape (see GBK bypass in note 38) |
| `NUL (0x00)` | Truncates strings in C-level parsers, potentially cutting off escape characters |
| `LF (0x0a)` / `CR (0x0d)` | Can break out of single-line SQL comments (`--` only comments to end of line) |
| `SUB (0x1a)` | Acts as EOF in Windows — can truncate input processing |
| `%` and `_` | LIKE wildcards — `WHERE name LIKE '$input'` with `%` matches everything |

### Limitations of Escaping

Even with proper escaping, vulnerabilities remain:
- **Unquoted numeric parameters** — escaping only helps inside quotes (see note 40)
- **Multi-byte encoding bypass** — GBK/Big5 can consume the backslash (see note 38)
- **Second-order injection** — escaped data stored in DB, then used unescaped in a later query
- **LIKE wildcards** — `%` and `_` may not be escaped by all functions, allowing data exfiltration via LIKE pattern matching

## ESAPI SQL Encoding — Database-Specific

OWASP ESAPI provides database-specific encoders that understand each database's escaping rules:

```java
Codec ORACLE_CODEC = new OracleCodec();

String query = "SELECT user_id FROM user_data WHERE user_name = '"
  + ESAPI.encoder().encodeForSQL(ORACLE_CODEC, req.getParameter("userID"))
  + "' and user_password = '"
  + ESAPI.encoder().encodeForSQL(ORACLE_CODEC, req.getParameter("pwd"))
  + "'";
```

### Why Database-Specific Encoding?

Different databases have different escaping rules:

| Database | Quote escape | Other differences |
|----------|-------------|-------------------|
| **MySQL** | `\'` or `''` | Backslash escaping, `\0`, `\n`, etc. |
| **Oracle** | `''` only | No backslash escaping; `'` is doubled to `''` |
| **SQL Server** | `''` only | No backslash escaping; uses `[]` for identifiers |
| **PostgreSQL** | `''` or `\'` | Depends on `standard_conforming_strings` setting |

Using MySQL escaping rules on an Oracle database would leave it vulnerable — `\'` doesn't escape in Oracle (the backslash is literal, and the quote still closes the string).

ESAPI's `OracleCodec`, `MySQLCodec`, `DB2Codec`, etc. each implement the correct rules for their database.

### ESAPI Encoding vs Parameterized Queries

| | ESAPI Encoding | Parameterized Queries |
|---|---------------|----------------------|
| **How it works** | Escapes special characters in the string | Separates SQL structure from data at protocol level |
| **Quote context required** | Yes — value must be inside quotes | No |
| **Encoding bugs possible** | Yes — wrong codec, missed parameter | No — structurally impossible to inject |
| **Use when** | Legacy code where prepared statements can't be retrofitted | All new code |
| **Recommendation** | Acceptable fallback | **Preferred approach** |

**ESAPI encoding is a second-best option** for situations where parameterized queries can't be used (dynamic table names, ORDER BY columns, legacy systems). For everything else, use prepared statements.
