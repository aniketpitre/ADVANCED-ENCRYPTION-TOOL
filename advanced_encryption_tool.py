#!/usr/bin/env python3
"""
Advanced Encryption Tool

This tool encrypts and decrypts files using AES-256 in CBC mode with PKCS7 padding.
A key is derived from a user-supplied password using PBKDF2HMAC with SHA256.

Usage:
    To encrypt a file:
        python advanced_encryption_tool.py encrypt -i plaintext.txt -o encrypted.bin -p "your_password"
    
    To decrypt a file:
        python advanced_encryption_tool.py decrypt -i encrypted.bin -o decrypted.txt -p "your_password"
        
The encrypted file format is as follows:
    [16 bytes salt][16 bytes IV][encrypted data]
"""

import os
import argparse
import sys
from base64 import urlsafe_b64encode, urlsafe_b64decode

from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Constants
SALT_SIZE = 16           # 16 bytes for salt
IV_SIZE = 16             # 16 bytes for AES block (128-bit)
KEY_SIZE = 32            # 32 bytes for AES-256
ITERATIONS = 100000      # Number of iterations for PBKDF2

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a secret key from the given password and salt using PBKDF2HMAC.
    
    :param password: The password provided by the user.
    :param salt: The salt to use for key derivation.
    :return: A 32-byte key for AES-256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(input_path: str, output_path: str, password: str):
    """
    Encrypts a file using AES-256 in CBC mode.
    
    The output file format is: [salt][IV][encrypted data].
    
    :param input_path: Path to the plaintext file.
    :param output_path: Path where the encrypted file will be saved.
    :param password: The password to derive the encryption key.
    """
    # Read the plaintext file
    try:
        with open(input_path, 'rb') as f:
            plaintext = f.read()
    except FileNotFoundError:
        sys.exit(f"Error: Input file '{input_path}' not found.")
    
    # Generate a random salt and IV
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(IV_SIZE)
    
    # Derive key from password and salt
    key = derive_key(password, salt)
    
    # Pad the plaintext to a multiple of the block size (AES block size is 128 bits = 16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    # Encrypt using AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # Write salt, IV, and ciphertext to the output file
    with open(output_path, 'wb') as f:
        f.write(salt + iv + ciphertext)
    
    print(f"[+] File '{input_path}' has been encrypted and saved as '{output_path}'.")

def decrypt_file(input_path: str, output_path: str, password: str):
    """
    Decrypts a file that was encrypted using the encrypt_file function.
    
    Expects the input file to have the following format: [salt][IV][encrypted data].
    
    :param input_path: Path to the encrypted file.
    :param output_path: Path where the decrypted file will be saved.
    :param password: The password to derive the decryption key.
    """
    # Read the encrypted file
    try:
        with open(input_path, 'rb') as f:
            file_data = f.read()
    except FileNotFoundError:
        sys.exit(f"Error: Input file '{input_path}' not found.")
    
    # Extract salt, IV, and ciphertext
    if len(file_data) < SALT_SIZE + IV_SIZE:
        sys.exit("Error: Encrypted file is too short or corrupted.")
    
    salt = file_data[:SALT_SIZE]
    iv = file_data[SALT_SIZE:SALT_SIZE+IV_SIZE]
    ciphertext = file_data[SALT_SIZE+IV_SIZE:]
    
    # Derive key from password and salt
    key = derive_key(password, salt)
    
    # Decrypt using AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    except ValueError:
        sys.exit("Error: Incorrect decryption. Possibly wrong password or corrupted file.")
    
    # Write the decrypted data to the output file
    with open(output_path, 'wb') as f:
        f.write(plaintext)
    
    print(f"[+] File '{input_path}' has been decrypted and saved as '{output_path}'.")

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Encryption Tool using AES-256"
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Commands: encrypt or decrypt")
    
    # Encrypt sub-command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("-i", "--input", required=True, help="Path to the input file to encrypt")
    encrypt_parser.add_argument("-o", "--output", required=True, help="Path to save the encrypted file")
    encrypt_parser.add_argument("-p", "--password", required=True, help="Password for encryption")
    
    # Decrypt sub-command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("-i", "--input", required=True, help="Path to the input file to decrypt")
    decrypt_parser.add_argument("-o", "--output", required=True, help="Path to save the decrypted file")
    decrypt_parser.add_argument("-p", "--password", required=True, help="Password for decryption")
    
    args = parser.parse_args()
    
    if args.command == "encrypt":
        encrypt_file(args.input, args.output, args.password)
    elif args.command == "decrypt":
        decrypt_file(args.input, args.output, args.password)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
