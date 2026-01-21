---
layout: post
title: "The Anatomy of SHA-256: A From-Scratch Guide in Python"
date: 2026-01-21
---

# 🔐 The Anatomy of SHA-256: A From-Scratch Guide in Python

SHA-256 is the cryptographic standard used everywhere from Bitcoin to SSL certificates. While most developers treat it as a "black box" through libraries like `hashlib`, the underlying logic is a masterpiece of bit-level manipulation. 

In this guide, we implement SHA-256 using **pure Python** to expose the mechanics of message padding, word expansion, and the 64-round compression loop.

---

## 🏗 High-Level Architecture

SHA-256 is a Merkle–Damgård construction. It takes an arbitrary-length input and produces a fixed 256-bit output. The security of this output relies on four pillars: **Pre-image Resistance**, **Collision Resistance**, **Efficiency**, and the **Avalanche Effect**.



---

## 🛠 Step 1: Pre-processing & Padding

The algorithm processes data in discrete **512-bit blocks**. Since real-world data rarely fits this size perfectly, we must apply a specific padding scheme to reach the nearest multiple of 512.

### The Padding Protocol:
1. **The Separator:** A single `1` bit is appended to the end of the raw message.
2. **Zero Padding:** Enough `0` bits are added to bring the total length to 448 bits.
3. **Length Encoding:** The final 64 bits are reserved for the binary representation of the original message length.

This structure ensures that messages of different lengths will always result in unique bitstreams before hashing begins.

---

## 🧮 Step 2: The Logic of Constants

SHA-256 utilizes two sets of constants that act as the "initial state" and "entropy source." These are derived from irrational numbers to prevent any mathematical bias.

### Initial Hash Values (H)
The 8 working variables ($a$ through $h$) start as the first 32 bits of the fractional parts of the **square roots** of the first 8 primes (2, 3, 5, 7, 11, 13, 17, 19).

### Round Constants (K)
There are 64 unique constants used in the compression rounds. These represent the first 32 bits of the fractional parts of the **cube roots** of the first 64 primes. Using cube roots ensures a high-entropy distribution of bits, making the mixing process cryptographically secure.

---

## 🔄 Step 3: Message Schedule Expansion

Each 512-bit block is initially split into sixteen 32-bit words ($W_0$ to $W_{15}$). To provide data for all 64 rounds of compression, we must expand these 16 words into 64.

This expansion uses the $\sigma_0$ and $\sigma_1$ functions, which apply bitwise **Right Rotate (ROTR)** and **Right Shift (SHR)**. This ensures that every bit of the original message is diffused across the entire schedule.



---

## 💥 Step 4: The 64-Round Compression Loop

The compression loop is the "washing machine" where the actual hashing occurs. The 8 working variables ($a$ to $h$) are mutated through 64 iterations of mixing logic.

### Core Functions:
* **Majority (`maj`):** A bitwise operation that returns the bit value appearing most frequently in three separate variables.
* **Choice (`ch`):** A conditional bitwise gate. If a bit in $X$ is 1, it takes the bit from $Y$; otherwise, it takes it from $Z$.
* **Rotation:** Circular bit shifts ensure that no bit stays in the same position for long, driving the **Avalanche Effect**.



---

## 🐍 The Complete Python Implementation

The following implementation requires no external dependencies and follows the official FIPS 180-4 standard.

```python
def sha256_simple(message):
    # --- HELPER FUNCTIONS ---
    def to_binary(msg):
        return ''.join(f"{ord(c):08b}" for c in msg)

    def rightrotate(x, n):
        # Wraps bits around the 32-bit boundary
        return (x >> n | x << (32 - n)) & 0xFFFFFFFF

    # --- 1. PADDING ---
    bin_msg = to_binary(message)
    original_len = len(bin_msg)
    
    bin_msg += '1'
    while (len(bin_msg) + 64) % 512 != 0:
        bin_msg += '0'
    bin_msg += f"{original_len:064b}"

    # --- 2. THE CONSTANTS ---
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # --- 3. PROCESSING ---
    chunks = [bin_msg[i:i+512] for i in range(0, len(bin_msg), 512)]

    for chunk in chunks:
        # Word Expansion (16 -> 64)
        w = [int(chunk[i:i+32], 2) for i in range(0, 512, 32)]
        for i in range(16, 64):
            s0 = rightrotate(w[i-15], 7) ^ rightrotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = rightrotate(w[i-2], 17) ^ rightrotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)

        a, b, c, d, e, f, g, h = H

        # Compression Loop
        for i in range(64):
            S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
            
            S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            # Variable Rotation
            h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF

        # Merge results with existing hash state
        H = [(x + y) & 0xFFFFFFFF for x, y in zip(H, [a, b, c, d, e, f, g, h])]

    return ''.join(f"{value:08x}" for value in H)

# --- EXECUTION ---
user_input = "Cryptography Explained"
print(f"Input: {user_input}")
print(f"SHA-256: {sha256_simple(user_input)}")
