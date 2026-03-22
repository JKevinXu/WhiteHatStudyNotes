# 33 - SQL Injection: Basics and Detection

## What Is SQL Injection?

SQL injection occurs when user input is concatenated directly into a SQL query without sanitization, allowing the attacker to modify the query's logic.

## Classic Example: String Concatenation

### The Vulnerable Code

```asp
var ShipCity;
ShipCity = Request.form("ShipCity");
var sql = "select * from OrdersTable where ShipCity = '" + ShipCity + "'";
```

User input (`ShipCity`) is dropped directly into the SQL string.

### Normal Input

User enters: `Beijing`

```sql
SELECT * FROM OrdersTable WHERE ShipCity = 'Beijing'
```

Works as expected — returns orders shipped to Beijing.

### Malicious Input

User enters: `Beijing'; drop table OrdersTable--`

```sql
SELECT * FROM OrdersTable WHERE ShipCity = 'Beijing'; drop table OrdersTable--'
```

**What the database sees:**

| Part | What it does |
|------|-------------|
| `SELECT * FROM OrdersTable WHERE ShipCity = 'Beijing'` | The original query (completes normally) |
| `;` | Statement separator — starts a new query |
| `drop table OrdersTable` | Deletes the entire table |
| `--` | SQL comment — ignores the trailing `'` that would cause a syntax error |

The `--` at the end is critical: the original code appends a closing `'`, which would break the injected SQL. The comment marker neutralizes it.

## Detecting SQL Injection

### Error-Based Detection

When testing for injection, submitting a single quote `'` often triggers a database error:

```
Microsoft JET Database Engine错误 '80040e14'
字符串的语法错误 在查询表达式 'ID=49'' 中。
/showdetail.asp，行8
```

This error reveals:
- **The database type** — Microsoft JET (Access database)
- **The query structure** — `ID=49'` shows how the input is placed in the query
- **The file path** — `/showdetail.asp` line 8

Detailed error messages are a goldmine for attackers. They confirm SQL injection exists and reveal the database engine, query structure, and server paths.

### Numeric vs String Parameters

**Numeric parameter (no quotes):**

```sql
select xxx from table_X where id = $id
```

For numeric parameters, the attacker doesn't need to escape quotes. Input `1; drop table table_X--` works directly:

```sql
select xxx from table_X where id = 1; drop table table_X--
```

**String parameter (quoted):**

```sql
select * from OrdersTable where ShipCity = '$input'
```

The attacker must first close the quote with `'`, then inject: `Beijing'; drop table OrdersTable--`

### Detection Techniques Summary

| Test Input | What to look for |
|-----------|-----------------|
| `'` (single quote) | Database error message (syntax error) |
| `1 OR 1=1` | Returns more rows than expected (always true) |
| `1 AND 1=2` | Returns no rows (always false) — confirms input affects the query |
| `1; SELECT 1--` | Stacked query execution (if supported) |
| `1 UNION SELECT null--` | Column count enumeration |
| Time-based: `1; WAITFOR DELAY '0:0:5'--` | Response delayed by 5 seconds (blind injection) |

### Types of SQL Injection

| Type | Description |
|------|-------------|
| **In-band (classic)** | Results visible in the response (error messages, extra data) |
| **Blind (boolean)** | No visible output; infer data from true/false response differences |
| **Blind (time-based)** | No visible output; infer data from response time delays |
| **Out-of-band** | Data exfiltrated via DNS, HTTP requests from the database server |
| **Stacked queries** | Multiple statements via `;` — not all databases/drivers support this |
