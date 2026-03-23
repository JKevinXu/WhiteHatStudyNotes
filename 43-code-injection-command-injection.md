# 43 - Code Injection and OS Command Injection

## Code Injection — Executing Arbitrary Code

Code injection occurs when user input is passed to a language interpreter (eval, script engine) and executed as code.

### PHP — eval() Injection

```php
$myvar = "varname";
$x = $_GET['arg'];
eval("\$myvar = $x;");
```

**Normal request:**

```
/index.php?arg=1
```

eval executes: `$myvar = 1;` — assigns 1 to the variable.

**Malicious request:**

```
/index.php?arg=1;phpinfo()
```

eval executes: `$myvar = 1; phpinfo();` — the semicolon terminates the first statement, then `phpinfo()` executes, revealing server configuration, PHP version, loaded modules, and environment variables.

The attacker can escalate further: `arg=1;system('whoami')` gives OS command execution.

### Java — ScriptEngine eval() Injection

```java
import javax.script.*;

public class Example1 {
    public static void main(String[] args) {
        try {
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");
            System.out.println(args[0]);
            engine.eval("print('" + args[0] + "')");
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
}
```

**Normal input:** `hello` → executes `print('hello')`

**Malicious input:**

```
hallo'); var fImport = new JavaImporter(java.io.File); with(fImport) { var f = new File('new'); f.createNewFile(); } //
```

**What the engine executes:**

```javascript
print('hallo');
var fImport = new JavaImporter(java.io.File);
with(fImport) {
    var f = new File('new');
    f.createNewFile();
}
//')
```

The attacker:
1. Closes the string and statement with `hallo');`
2. Uses `JavaImporter` to access Java's `java.io.File` class from JavaScript
3. Creates a new file on the server filesystem
4. Comments out the trailing `')` with `//`

**Java's ScriptEngine can access the full Java API** — file I/O, network, runtime execution. This makes script injection in Java as dangerous as native code execution.

## OS Command Injection

OS command injection occurs when user input is passed to a system shell via functions like `system()`, `exec()`, or backticks.

### PHP — system() Injection

```php
<?php
$varerror = system('cat ' . $_GET['pageid'], $valoretorno);
echo $varerror;
?>
```

**Normal request:**

```
vulnerable.php?pageid=readme.txt
```

Executes: `cat readme.txt` — displays the file contents.

**Malicious request:**

```
vulnerable.php?pageid=loquesea;ls
```

Executes: `cat loquesea; ls`

The shell interprets `;` as a command separator:
1. `cat loquesea` — fails (file doesn't exist), but doesn't stop execution
2. `ls` — lists directory contents, revealing server files

### C — Command Injection via String Concatenation

```c
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char cat[] = "cat ";
    char *command;
    size_t commandLength;

    commandLength = strlen(cat) + strlen(argv[1]) + 1;
    command = (char *) malloc(commandLength);
    strncpy(command, cat, commandLength);
    strncat(command, argv[1], (commandLength - strlen(cat)));

    system(command);
    return (0);
}
```

**Normal usage:**

```
$ ./catWrapper Story.txt
When last we left our heroes...
```

Executes: `cat Story.txt`

**Malicious usage:**

```
$ ./catWrapper "Story.txt; ls"
When last we left our heroes...
Story.txt              doubFree.c            nullpointer.c
unstosig.c             www*                  a.out*
format.c               strlen.c              useFree*
catWrapper*            misnull.c             strlength.c           useFree.c
commandinjection.c     nodefault.c           trunc.c               writeWhatWhere.c
```

Executes: `cat Story.txt; ls` — reads the file, then lists the directory.

### Shell Metacharacters for Injection

The shell interprets these characters as command separators or operators:

| Character | Meaning | Example |
|-----------|---------|---------|
| `;` | Command separator | `cmd1; cmd2` — run both sequentially |
| `&&` | AND — run second if first succeeds | `cmd1 && cmd2` |
| `\|\|` | OR — run second if first fails | `cmd1 \|\| cmd2` |
| `\|` | Pipe — feed output of first to second | `cmd1 \| cmd2` |
| `` ` `` | Command substitution | `` cmd1 `cmd2` `` — runs cmd2 first |
| `$()` | Command substitution | `cmd1 $(cmd2)` — runs cmd2 first |
| `>` | Redirect output | `cmd > file` — overwrites file |
| `<` | Redirect input | `cmd < file` — reads from file |
| `\n` (newline) | Command separator | URL-encoded as `%0a` |

### Code Injection vs Command Injection vs SQL Injection

| | Code Injection | Command Injection | SQL Injection |
|---|---------------|-------------------|---------------|
| **Target** | Language interpreter (eval, ScriptEngine) | OS shell (bash, cmd.exe) | Database engine |
| **Payload** | PHP/JS/Python code | Shell commands | SQL statements |
| **Via** | `eval()`, `ScriptEngine.eval()` | `system()`, `exec()`, backticks | Query string concatenation |
| **Impact** | Arbitrary code in app context | OS command as app user | Database read/write/file access |

## Defenses

| Defense | How |
|---------|-----|
| **Never use eval()** | Almost always unnecessary; use data structures, config files, or safe parsers instead |
| **Never pass user input to system()** | Use language-native APIs (e.g., PHP's `file_get_contents()` instead of `system('cat ...')`) |
| **Input validation (whitelist)** | Allow only expected characters (alphanumeric, specific symbols) |
| **Parameterized commands** | Use `execvp()` with argument arrays instead of `system()` with strings — arguments are never parsed by the shell |
| **Escape shell metacharacters** | PHP: `escapeshellarg()`, `escapeshellcmd()` — last resort, not recommended |
