# 38 - SQL Injection: SQL Server, Oracle, and Encoding Bypasses

## SQL Server — xp_cmdshell

SQL Server provides built-in **extended stored procedures** that interact directly with the OS.

### OS Command Execution

```sql
EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:'
EXEC master.dbo.xp_cmdshell 'ping 10.0.0.1'
```

`xp_cmdshell` executes any OS command and returns the output as rows. Unlike MySQL UDFs which require uploading a shared library, SQL Server ships with this capability built-in.

### Enabling xp_cmdshell (Disabled by Default Since SQL Server 2005)

```sql
EXEC sp_configure 'show advanced options', 1
RECONFIGURE

EXEC sp_configure 'xp_cmdshell', 1
RECONFIGURE
```

If the attacker has `sysadmin` privileges, they can re-enable `xp_cmdshell` even after an administrator disabled it.

### Registry Access

```sql
-- Read registry values
exec xp_regread HKEY_LOCAL_MACHINE,
  'SYSTEM\CurrentControlSet\Services\lanmanserver\parameters',
  'nullsessionshares'

-- Enumerate registry values
exec xp_regenumvalues HKEY_LOCAL_MACHINE,
  'SYSTEM\CurrentControlSet\Services\snmp\parameters\validcommunities'
```

`xp_regread` and `xp_regenumvalues` read the Windows registry directly from SQL. The attacker can:
- Read SNMP community strings (often used for network device access)
- Discover null session shares (open file shares)
- Find installed software, service configurations, network settings

### Service Control

```sql
exec master..xp_servicecontrol 'start', 'schedule'
exec master..xp_servicecontrol 'start', 'server'
```

Start or stop Windows services from SQL — the attacker can enable services needed for further exploitation (e.g., start the Task Scheduler for persistence).

### SQL Server vs MySQL — Command Execution Comparison

| | MySQL | SQL Server |
|---|-------|-----------|
| **Built-in OS access** | No (requires UDF upload) | Yes (`xp_cmdshell`) |
| **Setup required** | Upload `.so`, CREATE FUNCTION | Just enable via `sp_configure` |
| **Registry access** | No | Yes (`xp_regread`, `xp_regenumvalues`) |
| **Service control** | No (must use `system()`) | Yes (`xp_servicecontrol`) |
| **Privilege needed** | FILE + CREATE FUNCTION | `sysadmin` role |

## Oracle — PL/SQL Injection

### Dynamic SQL in Stored Procedures

```sql
procedure get_item (
    itm_cv IN OUT ItmCurTyp,
    usr in varchar2,
    itm in varchar2)
is
    open itm_cv for ' SELECT * FROM items WHERE ' ||
              'owner = '''|| usr ||
              ' AND itemname = ''' || itm || '''';
end get_item;
```

This Oracle PL/SQL procedure builds a query by concatenating user input (`usr`, `itm`) directly into the SQL string — the same vulnerability pattern as PHP/ASP string concatenation.

**Normal call:**

```
usr = 'admin', itm = 'widget'
→ SELECT * FROM items WHERE owner = 'admin' AND itemname = 'widget'
```

**Injection:**

```
usr = "admin'--", itm = (anything)
→ SELECT * FROM items WHERE owner = 'admin'--' AND itemname = '...'
```

The `--` comments out the rest, bypassing the `itemname` filter. The attacker sees all items owned by admin.

**Key point:** SQL injection exists in **stored procedures** too, not just in web application code. If a stored procedure builds dynamic SQL with concatenation, it's vulnerable regardless of what the calling application does.

## Encoding Bypasses — Defeating addslashes()

### PHP addslashes()

```
Description:
string addslashes(string $str)
Returns a string with backslashes before characters that need
to be quoted in database queries. These characters are:
single quote ('), double quote ("), backslash (\) and NUL (NULL byte).
```

`addslashes()` escapes quotes by prepending a backslash: `'` becomes `\'`. This seems safe — the attacker can't close the string. But it fails against **multi-byte character encodings**.

### What Is Character Encoding?

Computers store text as bytes. An **encoding** defines how bytes map to characters.

**Single-byte encodings (ASCII, Latin-1):** every byte is one character.

```
Byte stream:   48  65  6C  6C  6F
Characters:     H   e   l   l   o
               (1 byte = 1 character, always)
```

**Multi-byte encodings (GBK, Shift-JIS, Big5):** some characters use 2 bytes.

```
GBK byte stream:   C4  E3  BA  C3
Characters:          你       好
                  (2 bytes = 1 character for Chinese chars)
```

In GBK, if the first byte is in the range `0x81-0xFE`, the next byte is part of the same character. This is where the vulnerability comes from.

### Simple Example: How addslashes() Normally Works

**Normal input (ASCII only):**

```php
$input = "admin' OR 1=1--";
$safe  = addslashes($input);
// Result: "admin\' OR 1=1--"
```

```sql
SELECT * FROM users WHERE name = 'admin\' OR 1=1--'
-- The \' keeps the quote escaped. The string doesn't close. Safe.
```

The backslash `\` tells MySQL: "the next `'` is literal, not a string terminator." The injection fails.

### GBK Encoding Bypass (Wide-Byte Injection)

Now the attacker sends a carefully crafted byte sequence:

```
0xbf27 or 1=1
```

The `0xbf` byte is the key — it's in the GBK leading byte range (`0x81-0xFE`).

**What happens step by step:**

```
Step 1: Attacker's raw input (bytes)
┌──────┬──────┬──────────────────────┐
│ 0xBF │ 0x27 │  or 1=1              │
│  ?   │  '   │                      │
└──────┴──────┴──────────────────────┘
         ↑ addslashes sees this quote and inserts 0x5C before it

Step 2: After addslashes() processes the bytes
┌──────┬──────┬──────┬──────────────────────┐
│ 0xBF │ 0x5C │ 0x27 │  or 1=1              │
│  ?   │  \   │  '   │                      │
└──────┴──────┴──────┴──────────────────────┘
  addslashes thinks: BF is harmless, then \' is an escaped quote. Safe!

Step 3: MySQL receives the bytes and interprets them as GBK
┌───────────┬──────┬──────────────────────┐
│ 0xBF 0x5C │ 0x27 │  or 1=1              │
│    縗      │  '   │                      │
└───────────┴──────┴──────────────────────┘
  MySQL GBK parser: BF is a leading byte (0x81-0xFE range),
  so BF+5C = one Chinese character. The backslash is GONE.
  0x27 is now a standalone, unescaped single quote!
```

**The resulting SQL:**

```sql
-- What addslashes thinks it produced:
SELECT * FROM users WHERE name = '縗\' or 1=1'
--                                  ↑ escaped quote, string continues

-- What the GBK-aware MySQL actually sees:
SELECT * FROM users WHERE name = '縗' or 1=1'
--                                   ↑ string ends here!
--                                     ↑ injected condition executes!
```

The quote is free, and `or 1=1` executes. The attacker bypasses authentication or extracts data.

### Why This Works — The Core Mismatch

```
addslashes()          MySQL (GBK mode)
─────────────         ────────────────
Sees BYTES            Sees CHARACTERS
1 byte = 1 char       Some byte pairs = 1 char

0xBF = one char       0xBF = "I need one more byte"
0x5C = one char (\)   0x5C = "...this completes the char: 縗"
0x27 = one char (')   0x27 = standalone quote (')
```

`addslashes()` operates on **bytes**, not **characters**. It sees `0x27` and inserts `0x5c` before it. But the GBK-aware MySQL interprets `0xbf5c` as a single two-byte character, consuming the backslash.

**The fundamental problem:** the escaping function and the database use **different rules** to parse the same byte stream. The escaping function thinks the backslash is a separate escape character. The database thinks the backslash is the second half of a Chinese character.

### Which Encodings Are Vulnerable?

Any multi-byte encoding where `0x5C` (backslash) can appear as the **second byte** of a two-byte character:

| Encoding | Vulnerable? | Why |
|----------|-------------|-----|
| **GBK** | Yes | `0x5C` is a valid trailing byte |
| **Big5** | Yes | Same issue — `0x5C` in trailing byte range |
| **Shift-JIS** | Yes | Japanese encoding with same byte range overlap |
| **UTF-8** | **No** | Trailing bytes are always `0x80-0xBF` — `0x5C` is never part of a multi-byte sequence |
| **Latin-1** | **No** | Single-byte encoding — no multi-byte characters |

This is why **UTF-8 is safe** — its design guarantees that ASCII bytes (`0x00-0x7F`) are never "absorbed" into multi-byte sequences.

### Defenses Against Encoding Bypass

| Defense | Why it works |
|---------|-------------|
| **Parameterized queries** | Input is never part of the SQL syntax — encoding is irrelevant |
| **`mysql_real_escape_string()`** | Encoding-aware — knows the connection charset and escapes correctly |
| **`SET NAMES utf8` + UTF-8 everywhere** | UTF-8 doesn't have this byte-eating problem |
| **Never use `addslashes()` for SQL** | It's encoding-unaware and fundamentally broken for this purpose |
