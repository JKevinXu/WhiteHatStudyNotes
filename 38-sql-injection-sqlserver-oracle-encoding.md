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

### GBK Encoding Bypass (Wide-Byte Injection)

The attacker sends:

```
0xbf27 or 1=1
```

**What happens step by step:**

| Step | Data | Explanation |
|------|------|-------------|
| Input bytes | `0xbf 0x27` | `0x27` is `'` (single quote) |
| After addslashes | `0xbf 0x5c 0x27` | `0x5c` (`\`) is inserted before the quote |
| GBK interpretation | `0xbf5c` = `縗` (valid GBK char) + `0x27` = `'` | The backslash is "eaten" by the multi-byte character |

In GBK encoding (commonly used for Chinese text), `0xbf5c` is a valid two-byte character. The database sees:
- `縗` — a Chinese character (harmless)
- `'` — an unescaped single quote (injection!)

```sql
-- What addslashes thinks it produced:
SELECT * FROM users WHERE name = '縗\' or 1=1'

-- What the GBK-aware database actually sees:
SELECT * FROM users WHERE name = '縗' or 1=1'
```

The quote is free, and `or 1=1` executes.

### Why This Works

```
ASCII:  Each byte = one character
        0xbf = ¿    0x5c = \    0x27 = '

GBK:    Some byte pairs = one character
        0xbf5c = 縗              0x27 = '
        (the backslash is consumed as part of a two-byte character)
```

`addslashes()` operates on **bytes**, not **characters**. It sees `0x27` and inserts `0x5c` before it. But the GBK-aware MySQL interprets `0xbf5c` as a single character, consuming the backslash.

### Defenses Against Encoding Bypass

| Defense | Why it works |
|---------|-------------|
| **Parameterized queries** | Input is never part of the SQL syntax — encoding is irrelevant |
| **`mysql_real_escape_string()`** | Encoding-aware — knows the connection charset and escapes correctly |
| **`SET NAMES utf8` + UTF-8 everywhere** | UTF-8 doesn't have this byte-eating problem |
| **Never use `addslashes()` for SQL** | It's encoding-unaware and fundamentally broken for this purpose |
