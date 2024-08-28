import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Function to encrypt data
def encrypt_data(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext

# Function to decrypt data
def decrypt_data(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data

# Encrypt a file
def encrypt_file(file_path, key, iv):
    print(f"Encrypting file: {file_path}")
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = encrypt_data(file_data, key, iv)
    
    # Save the encrypted file with the IV and the key
    with open(file_path + '.enc', 'wb') as file:
        file.write(iv + encrypted_data)

    # Save the key in a separate file
    with open(file_path + '.key', 'wb') as key_file:
        key_file.write(key)

# Decrypt a file
def decrypt_file(encrypted_file_path):
    print(f"Decrypting file: {encrypted_file_path}")

    # Load the key from the separate file
    key_file_path = encrypted_file_path.rstrip('.enc') + '.key'
    if not os.path.exists(key_file_path):
        print(f"Error: Key file '{key_file_path}' not found.")
        return

    with open(key_file_path, 'rb') as key_file:
        key = key_file.read()

    # Load the IV and the encrypted data
    with open(encrypted_file_path, 'rb') as file:
        iv = file.read(16)  # First 16 bytes are the IV
        encrypted_data = file.read()

    try:
        decrypted_data = decrypt_data(encrypted_data, key, iv)
        decrypted_file_path = encrypted_file_path.rstrip('.enc')
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)
        print(f"File decrypted and saved as: {decrypted_file_path}")
    except ValueError as e:
        print(f"Decryption failed: {e}")

# Main function to handle user input
def main():
    mode = input("Choose mode (encrypt/decrypt): ").lower()
    data_type = input("Enter the type of data (string/file/folder): ").lower()

    if mode == 'encrypt':
        if data_type == 'file':
            file_path = input("Enter the file path to encrypt: ")
            key = get_random_bytes(16)  # Generate a new key
            iv = get_random_bytes(16)   # Generate a new IV
            encrypt_file(file_path, key, iv)
            print(f"File encrypted and saved as: {file_path}.enc")
        else:
            print("Invalid data type selected.")
    elif mode == 'decrypt':
        if data_type == 'file':
            encrypted_file_path = input("Enter the encrypted file path: ")
            decrypt_file(encrypted_file_path)
        else:
            print("Invalid data type selected.")
    else:
        print("Invalid mode selected.")

if __name__ == "__main__":
    main()
