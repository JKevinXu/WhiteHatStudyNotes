# 34 - Blind SQL Injection: Boolean-Based Detection

## The Scenario

A news website displays articles by ID:

```
http://newspaper.com/items.php?id=2
```

Server-side query:

```sql
SELECT title, description, body FROM items WHERE ID = 2
```

The page returns the article normally. No error messages are shown — the application hides database errors. This is where **blind SQL injection** comes in.

## Boolean-Based Blind Detection

The attacker can't see SQL errors or query output directly, but can observe whether the page **behaves differently** based on injected conditions.

### Step 1: Inject a False Condition

```
http://newspaper.com/items.php?id=2 and 1=2
```

```sql
SELECT title, description, body FROM items WHERE ID = 2 and 1=2
```

`1=2` is always **false**, so `ID = 2 AND 1=2` is false. The query returns **no rows**. The page shows:
- A blank page, or
- A "no article found" message, or
- A generic error page

This is noticeably **different** from the normal page.

### Step 2: Inject a True Condition

```
http://newspaper.com/items.php?id=2 and 1=1
```

```sql
SELECT title, description, body FROM items WHERE ID = 2 and 1=1
```

`1=1` is always **true**, so `ID = 2 AND 1=1` is equivalent to `ID = 2`. The query returns the same article. The page looks **exactly the same** as the normal page.

### Step 3: Compare the Two Responses

| Request | Condition | Page behavior |
|---------|-----------|--------------|
| `id=2` | Normal | Article displays |
| `id=2 and 1=1` | Always true | Article displays (same as normal) |
| `id=2 and 1=2` | Always false | Article missing (different) |

If the true condition shows the article and the false condition doesn't, the injected SQL is being **executed by the database**. SQL injection is confirmed — even though no error messages are visible.

## Extracting Data with Boolean Blind

Once injection is confirmed, the attacker can extract data **one bit at a time** by asking true/false questions:

```
id=2 and (SELECT length(password) FROM users WHERE username='admin') > 10
```

- Page shows article → password length is > 10 (true)
- Page is blank → password length is <= 10 (false)

```
id=2 and (SELECT substring(password,1,1) FROM users WHERE username='admin') = 'a'
```

- Page shows article → first character is 'a'
- Page is blank → first character is not 'a'

By iterating through positions and characters, the attacker can extract any value from the database — it's slow (one character at a time) but fully automated with tools like sqlmap.

## Why This Is Dangerous

- **No error messages needed** — the attacker only needs two distinguishable page states (article present vs absent)
- **Hiding errors doesn't help** — suppressing SQL errors prevents error-based injection but does nothing against blind injection
- **Automated tools make it fast** — sqlmap can extract entire databases via boolean blind injection using binary search on character values
