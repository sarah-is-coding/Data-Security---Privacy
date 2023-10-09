# Required libraries for AES operations and command-line argument parsing
import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

# Function to generate an AES secret key
def aes_keygen():
    # Generate a random 256-bit key for AES
    key = get_random_bytes(32)
    print(f"Generated Key: {key.hex()}")

    # Check if the 'data' directory exists; if not, create it
    if not os.path.exists("../data"):
        os.makedirs("../data")

    # Save the generated key in the 'data' directory as a hexadecimal string
    with open("../data/key.txt", "w") as key_file:
        key_file.write(key.hex())

# Function to encrypt a given plaintext using AES in CBC mode
def aes_enc(key_path, plaintext_path, ciphertext_path, iv_path):
    # Load the secret key from the provided path
    with open(key_path, "r") as key_file:
        key = bytes.fromhex(key_file.read().strip())
    
    # Load the plaintext data to be encrypted
    with open(plaintext_path, "r") as plaintext_file:
        plaintext = plaintext_file.read().encode()

    # Generate a random initialization vector (IV) for CBC mode
    iv = get_random_bytes(16)
    with open(iv_path, "w") as iv_file:
        iv_file.write(iv.hex())

    # Create an AES cipher object using the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Encrypt the plaintext
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Save the encrypted ciphertext to the provided path
    with open(ciphertext_path, "w") as ciphertext_file:
        ciphertext_file.write(ciphertext.hex())

    print("Encryption complete.")

# Function to decrypt a given ciphertext using AES in CBC mode
def aes_dec(key_path, iv_path, ciphertext_path, result_path):
    # Load the secret key and IV from their respective paths
    with open(key_path, "r") as key_file:
        key = bytes.fromhex(key_file.read().strip())
    
    with open(iv_path, "r") as iv_file:
        iv = bytes.fromhex(iv_file.read().strip())

    # Load the ciphertext data to be decrypted
    with open(ciphertext_path, "r") as ciphertext_file:
        ciphertext = bytes.fromhex(ciphertext_file.read().strip())

    # Create an AES cipher object using the key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    # Save the decrypted plaintext to the provided path
    with open(result_path, "w") as result_file:
        result_file.write(plaintext.decode('utf-8'))

    print("Decryption complete.")

# Main function to handle command-line interface of the script
def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="AES Encryption/Decryption Utility")
    
    # Define sub-commands: keygen, enc, dec
    subparsers = parser.add_subparsers(dest="command")

    # Define arguments for the 'keygen' sub-command
    keygen_parser = subparsers.add_parser("keygen")
    keygen_parser.add_argument("key_file", help="path to save the secret key")

    # Define arguments for the 'enc' sub-command
    enc_parser = subparsers.add_parser("enc")
    enc_parser.add_argument("key_file", help="path to the secret key file")
    enc_parser.add_argument("plaintext_file", help="path to the plaintext file")
    enc_parser.add_argument("ciphertext_file", help="path to save the ciphertext")

    # Define arguments for the 'dec' sub-command
    dec_parser = subparsers.add_parser("dec")
    dec_parser.add_argument("key_file", help="path to the secret key file")
    dec_parser.add_argument("ciphertext_file", help="path to the ciphertext file")
    dec_parser.add_argument("result_file", help="path to save the decrypted result")

    # Parse the provided command-line arguments
    args = parser.parse_args()

    # Execute the appropriate function based on the sub-command provided
    if args.command == "keygen":
        aes_keygen()
    elif args.command == "enc":
        aes_enc(args.key_file, args.plaintext_file, args.ciphertext_file, "../data/iv.txt")
    elif args.command == "dec":
        aes_dec(args.key_file, "../data/iv.txt", args.ciphertext_file, args.result_file)
    else:
        print("Invalid command. Use -h for help.")

if __name__ == "__main__":
    main()
