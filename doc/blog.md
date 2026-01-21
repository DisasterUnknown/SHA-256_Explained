# 🔐 The Anatomy of SHA-256: A From-Scratch Guide in Python

In the world of cybersecurity, **SHA-256** is the invisible backbone. It secures the passwords you type, the Bitcoin transactions you send, and the software updates your computer downloads. But for most developers, it remains a "black box" provided by libraries like `hashlib` or `OpenSSL`.

Today, we are breaking the box open. We will implement SHA-256 using **pure Python**, explaining every bit-shift and logical gate along the way. 

---

## 🧐 What is a Cryptographic Hash?

A hash function is a one-way street. It takes an input (a "message") and transforms it into a fixed-size string of characters, which looks like random noise. 



### The Requirements for Greatness:
1. **Pre-image Resistance:** If I give you a hash, you should never be able to find the original message.
2. **Collision Resistance:** It should be nearly impossible to find two different messages that produce the exact same hash.
3. **Efficiency:** It must be fast to compute.
4. **The Avalanche Effect:** If you change one single bit in the input, at least half of the bits in the output hash should change.

---

## 🛠 Step 1: Pre-processing & Padding

Computers don't hash "text"; they hash **bits**. SHA-256 processes data in blocks of **512 bits**. If your message isn't exactly a multiple of 512, we have to "pad" it.

### The Padding Rule:
1. Append a single `1` bit to the end of the message.
2. Append `0` bits until the message length is exactly 448 bits (leaving 64 bits of space at the end).
3. In those final 64 bits, encode the **length of the original message**.

This ensures that even if two messages are identical except for their length, their hashes will be completely different.

---

## 🧮 Step 2: The Magic Constants

SHA-256 uses two sets of "magic" numbers. These aren't random; they are derived from prime numbers to ensure there are no "backdoors."

### Initial Hash Values (H)
These are the starting points for the 8 working variables ($a$ through $h$). They are the first 32 bits of the fractional parts of the **square roots** of the first 8 primes (2 through 19).

### Round Constants (K)
There are 64 constants, one for each round of the compression loop. These are the first 32 bits of the fractional parts of the **cube roots** of the first 64 primes (2 through 311).

> **Why cube roots?** It provides a high-entropy distribution of bits, making the internal mixing much more complex for an attacker to predict.

---

## 🔄 Step 3: Message Expansion

Each 512-bit block is broken into sixteen 32-bit "words." However, the algorithm runs for 64 rounds. We need to expand those 16 words into **64 words**.

This is done using two mathematical functions, $\sigma_0$ (Sigma0) and $\sigma_1$ (Sigma1), which involve rotating and shifting the bits of previous words.



---

## 💥 Step 4: The Compression Loop

This is the "meat" of the algorithm. We take our 8 working variables and put them through a "washing machine" of 64 rounds. 

In each round, we use:
* **The Majority Function (`maj`):** Returns the bit that appears most often in three variables.
* **The Choice Function (`ch`):** If a bit in $X$ is 1, it chooses a bit from $Y$; if it's 0, it chooses from $Z$.
* **Rotations:** Bits are shifted in a circle, so bits falling off the right side reappear on the left.

---

## 🐍 The Complete Python Implementation

Here is the full code. Save this as `sha256.py` and run it!

```python
def sha256_simple(message):
    # --- INTERNAL HELPERS ---
    def to_binary(msg):
        return ''.join(f"{ord(c):08b}" for c in msg)

    def rightrotate(x, n):
        # Keeps it within 32-bit boundaries using & 0xFFFFFFFF
        return (x >> n | x << (32 - n)) & 0xFFFFFFFF

    # --- 1. PADDING ---
    bin_msg = to_binary(message)
    original_len = len(bin_msg)
    
    bin_msg += '1'
    while (len(bin_msg) + 64) % 512 != 0:
        bin_msg += '0'
    bin_msg += f"{original_len:064b}"

    # --- 2. CONSTANTS ---
    # Cube roots of first 64 primes
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

    # Initial square roots of first 8 primes
    H = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    # --- 3. PROCESSING ---
    chunks = [bin_msg[i:i+512] for i in range(0, len(bin_msg), 512)]

    for chunk in chunks:
        # Create 64 words
        w = [int(chunk[i:i+32], 2) for i in range(0, 512, 32)]
        for i in range(16, 64):
            s0 = rightrotate(w[i-15], 7) ^ rightrotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = rightrotate(w[i-2], 17) ^ rightrotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)

        # Initialize working variables
        a, b, c, d, e, f, g, h = H

        # Main Compression Loop
        for i in range(64):
            S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[i] + w[i]) & 0xFFFFFFFF
            
            S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            # Shift variables
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        # Add this chunk's result to total hash
        H = [(x + y) & 0xFFFFFFFF for x, y in zip(H, [a, b, c, d, e, f, g, h])]

    # Final digest construction
    return ''.join(f"{value:08x}" for value in H)

# --- EXECUTION ---
user_input = "Python Cryptography"
print(f"Input: {user_input}")
print(f"SHA-256: {sha256_simple(user_input)}")
