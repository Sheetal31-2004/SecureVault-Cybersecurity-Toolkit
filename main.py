from crypto_utils import generate_key, load_key, encrypt_message, decrypt_message

# Step 1: Generate the key file (do this ONCE)
generate_key()  # <-- Run this line once to create secret.key

# Step 2: Load the key
key = load_key()

# Step 3: Encrypt a message
message = input("Enter a secret message: ")
encrypted = encrypt_message(message, key)
print(f"Encrypted: {encrypted}")

# Step 4 (optional): Decrypt it back
decrypted = decrypt_message(encrypted, key)
print(f"Decrypted: {decrypted}")
