# Vulnerability Analysis of Merkle-Damgård Construction: Length Extension Attack on SHA-1

## 📌 Project Overview

This project demonstrates the **Length Extension Attack**, a critical cryptographic vulnerability inherent in hash functions built upon the Merkle-Damgård construction (such as MD5, SHA-1, and SHA-2).

Specifically, this project proves that using a naive "Secret Prefix" construction for Message Authentication Codes—defined as `MAC = SHA1(Secret_Key || Message)`—is fundamentally insecure. By implementing the SHA-1 algorithm completely from scratch, this simulation allows an attacker to intercept a valid digital signature, extract the internal state of the hash engine, and forge a valid signature for a malicious payload without ever knowing the secret key.

## ✨ Features

* **Custom SHA-1 Implementation:** A from-scratch, bitwise implementation of the SHA-1 algorithm adhering to RFC 3174 (bypassing standard libraries like `hashlib` to expose internal state registers).
* **State Resumption Engine:** A custom "backdoor" function that allows the hash engine to be paused and resumed from a stolen signature state.
* **Exact Padding Calculation:** Algorithms to calculate the exact Merkle-Damgård "glue" padding required to bridge the original message and the malicious extension.
* **Immersive GUI:** A Tkinter-based "Hacker Terminal" interface that visualizes the attack step-by-step.
* **Automated Validation:** A testing suite that runs 25 automated, randomized test cases and generates a graphical success rate chart to prove mathematical certainty.

## 🛠️ Prerequisites

This project is built using strictly standard Python libraries to meet "from scratch" academic requirements. No external cryptographic libraries are required.

* **Python 3.6 or higher**
* **Tkinter** (Usually comes pre-installed with standard Python distributions)

## 🚀 How to Run the Project

1. Open your terminal or command prompt.
2. Navigate to the directory containing the project file.
3. Run the following command:
```bash
python project_main.py

```


4. The GUI window will open automatically.

## 🎮 How to Use the Interface

### Tab 1: Manual Attack Demo

1. **The Server Side:** Look at the top section. The server has a hidden `Secret Key` and a standard `Message` (e.g., `file=report.pdf`). Click **SIGN MESSAGE** to generate the original, valid signature.
2. **The Attacker Side:** Look at the bottom section. Input a malicious payload (e.g., `&admin=true`).
3. Click **LAUNCH EXTENSION ATTACK**.
4. Watch the Terminal Log. The script will intercept the signature, calculate the padding, resume the internal SHA-1 state, and forge a new signature. It will then verify the forgery against the server's strict checks.

### Tab 2: Automated Validation

1. Click the **RUN 25 AUTOMATED TEST CASES** button.
2. The system will generate random secret keys and random messages, performing the attack 25 times in a row.
3. A bar graph will dynamically generate, proving the 100% mathematical success rate of the vulnerability.

## 🧮 The Mathematical Flaw (Briefly)

The Merkle-Damgård construction processes data in 512-bit blocks. The mathematical vulnerability lies in the fact that the final output of the hash is simply the internal state of the algorithm's registers ($A, B, C, D, E$) after the last block.

Because the system uses `H(Key || Message)`, an attacker can take the output hash, load it back into the $A, B, C, D, E$ registers, and continue feeding the algorithm new data. The server, when verifying, will unknowingly process the `Key || Message`, arrive at the exact same intermediate state, and then process the attacker's appended data, resulting in a perfectly matched hash.

## 🛡️ Prevention

To secure systems against this, the nested **HMAC (Hash-based Message Authentication Code)** construction must be used as defined in RFC 2104:
`HMAC(K, M) = H((K ⊕ opad) || H((K ⊕ ipad) || M))`
This hides the internal state of the hashing engine, making extension impossible.

