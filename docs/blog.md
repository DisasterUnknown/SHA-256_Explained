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
    # -----------------------------------------------
    # SHA-256 Simplified with Beginner-Friendly Comments + Math
    # -----------------------------------------------

    # STEP 1: Convert message to binary
    def to_binary(msg):
        # Convert each character into 8-bit binary using ASCII
        return ''.join(f"{ord(c):08b}" for c in msg)

    # STEP 2: Padding the message to meet SHA-256 format
    def pad_message(bin_msg):
        original_len = len(bin_msg)  # in bits
        bin_msg += '1'  # Append 1 bit
        while (len(bin_msg) + 64) % 512 != 0:
            bin_msg += '0'
        bin_msg += f"{original_len:064b}"  # Append original length in 64-bit binary
        return bin_msg

    # STEP 3: Divide message into 512-bit chunks
    def create_chunks(padded_msg):
        return [padded_msg[i:i+512] for i in range(0, len(padded_msg), 512)]

    # Extend chunk to 64 32-bit words
    def create_words(chunk):
        words = [int(chunk[i:i+32], 2) for i in range(0, 512, 32)]

        while len(words) < 64:
            # ROTR and SHR using bitwise
            s0 = (words[-15] >> 7 | words[-15] << (32 - 7)) ^ \
                 (words[-15] >> 18 | words[-15] << (32 - 18)) ^ \
                 (words[-15] >> 3)
            s1 = (words[-2] >> 17 | words[-2] << (32 - 17)) ^ \
                 (words[-2] >> 19 | words[-2] << (32 - 19)) ^ \
                 (words[-2] >> 10)

            # Explanation:
            # >> n = Shift bits right (same as floor division by 2ⁿ)
            # << n = Shift bits left (same as multiply by 2ⁿ)
            # Example: 1001 (9) >> 2 = 0010 (2) ⇒ 9 / 2² = 2
            # x >> 7 = x/2^7 ||| x << 7 = x * 2^7

            words.append((words[-16] + s0 + words[-7] + s1) & 0xFFFFFFFF)

        return words

    # STEP 4: Constants

    # K — 64 constant words: fractional part of cube roots of first 64 prime numbers (in hex)
    # Formula: K[i] = floor(2³² × frac(cube_root(p))) for prime p = 2, 3, 5, ..., 311
    # These are precomputed and fixed in SHA-256
    K = [int(x, 16) for x in """
        428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
        d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
        e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
        983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
        27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
        a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
        19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
        748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2
    """.split()]

    # H — Initial Hash Values: fractional parts of the square roots of the first 8 primes
    # Formula: H[i] = floor(2³² × frac(sqrt(p))) where p = 2, 3, 5, ..., 19
    H = [int(x, 16) for x in """
        6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19
    """.split()]

    # Helper function for circular right rotation
    def rightrotate(x, n):
        return (x >> n | x << (32 - n)) & 0xFFFFFFFF

    # STEP 5: SHA-256 Compression
    bin_msg = to_binary(message)
    padded = pad_message(bin_msg)
    chunks = create_chunks(padded)

    for chunk in chunks:
        w = create_words(chunk)
        a, b, c, d, e, f, g, h = H  # working vars

        for i in range(64):
            # Compression step: Mix and rotate
            S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25)
            ch = (e & f) ^ (~e & g)  # 'choose' function
            temp1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF

            S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)  # 'majority' function
            temp2 = (S0 + maj) & 0xFFFFFFFF

            # Update state
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Mix chunk hash into result
        H = [(x + y) & 0xFFFFFFFF for x, y in zip(H, [a, b, c, d, e, f, g, h])]

    # STEP 6: Final output — 256-bit digest in hex
    return ''.join(f"{value:08x}" for value in H)

# Run
print(sha256_simple("a"))  # Expected: ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb

