# Advanced Encryption Tool

A robust Python-based application to encrypt and decrypt files using advanced algorithms like AES-256. This tool leverages the [cryptography](https://cryptography.io/en/latest/) library to securely encrypt files using AES in CBC mode with PKCS7 padding. A key is derived from a user-provided password using PBKDF2HMAC, ensuring strong and secure encryption.

> **Disclaimer:**  
> Use this tool only on files you own or have permission to encrypt/decrypt. Always keep backups of your data. The authors are not responsible for any data loss or misuse.

## Features

- **AES-256 Encryption:** Uses AES with a 256-bit key for strong security.
- **Secure Key Derivation:** Derives keys from user passwords using PBKDF2HMAC with SHA-256 and a random salt.
- **File Encryption & Decryption:** Supports encryption and decryption of files with a simple command-line interface.
- **Robust Error Handling:** Includes checks for file existence, corrupted data, and incorrect decryption passwords.

## Prerequisites

- Python 3.6 or later
- [cryptography](https://cryptography.io/en/latest/) library

Install the `cryptography` library using pip:

```bash
pip install cryptography


python advanced_encryption_tool.py encrypt -i document.txt -o document.enc -p "your_strong_password"


python advanced_encryption_tool.py encrypt -i document.txt -o document.enc -p "Your_entered_password"
