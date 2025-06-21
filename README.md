# 🔐 SHA-256 Simplified — Python Implementation

Welcome to the simplest-yet-powerful explanation and code walkthrough of the **SHA-256** algorithm, built entirely in **pure Python**, no libraries needed. Perfect for students, hobbyists, or curious devs who want to *understand* how hashing works at the bit level.

---

## 🚀 What is this?

This project demystifies the **SHA-256** algorithm by **breaking it down into readable Python code** with super-detailed comments explaining every:

- 🔢 Bit-level transformation  
- 🧮 Math formula (like `K` from cube roots of primes)  
- 💥 Irreversible hash operations  
- 🔁 Bitwise shifting (e.g. `>>`, `<<`) in terms of powers of 2  
- 📦 Padding, chunking, word expansion, and final digest generation  

---

## 🧠 SHA-256 in a Nutshell

> SHA-256 is a cryptographic hash function that takes an input and returns a fixed-length 256-bit (64 hex chars) output => seemingly random and irreversible.

### 🔄 What Happens Internally:

1. **Message → Binary**  
2. **Padding** the message to fit 512-bit chunks  
3. **Breaking it** into 32-bit words and expanding to 64  
4. **Applying 64 rounds** of mixing with magic constants  
5. **Generating final 256-bit digest**  

> Learn more: [SHA-2 explained visually (sha256)](https://en.wikipedia.org/wiki/SHA-2)<br>
> Learn more: [SHA-2 explained visually (sha256)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

---

## 🧪 Example Output

```bash
Input:  "a"
Output: ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
