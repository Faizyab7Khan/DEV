import os
import glob
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# RSA key generation
def generate_rsa_keypair(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Save keys to files
def save_keys(private_key, public_key, priv_key_path, pub_key_path):
    with open(priv_key_path, 'wb') as priv_file:
        priv_file.write(private_key)
    with open(pub_key_path, 'wb') as pub_file:
        pub_file.write(public_key)

# Load RSA keys from files
def load_key(key_path):
    with open(key_path, 'rb') as key_file:
        return RSA.import_key(key_file.read())

# Encrypt data with RSA public key
def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data

# Decrypt data with RSA private key
def rsa_decrypt(encrypted_data, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data

# Encrypt a file with AES and encrypt the AES key with RSA
def encrypt_file(file_path, public_key):
    print(f"Encrypting file: {file_path}")
    key = get_random_bytes(16)  # AES key
    iv = get_random_bytes(16)   # AES IV
    
    with open(file_path, 'rb') as file:
        file_data = file.read()
    
    cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher_aes.encrypt(pad(file_data, AES.block_size))

    encrypted_key = rsa_encrypt(key, public_key)
    
    with open(file_path + '.enc', 'wb') as enc_file:
        enc_file.write(encrypted_key + iv + encrypted_data)

# Decrypt a file encrypted with AES and RSA
def decrypt_file(encrypted_file_path, private_key):
    print(f"Decrypting file: {encrypted_file_path}")
    
    with open(encrypted_file_path, 'rb') as enc_file:
        encrypted_key = enc_file.read(private_key.size_in_bytes())
        iv = enc_file.read(16)
        encrypted_data = enc_file.read()

    key = rsa_decrypt(encrypted_key, private_key)
    
    cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher_aes.decrypt(encrypted_data), AES.block_size)

    decrypted_file_path = encrypted_file_path.rstrip('.enc')
    with open(decrypted_file_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
    
    print(f"File decrypted and saved as: {decrypted_file_path}")

# Encrypt a string with RSA
def encrypt_string(data, public_key):
    encrypted_data = rsa_encrypt(data.encode(), public_key)
    return encrypted_data

# Decrypt a string with RSA
def decrypt_string(encrypted_data, private_key):
    decrypted_data = rsa_decrypt(encrypted_data, private_key)
    return decrypted_data.decode()

# Encrypt all files in a folder
def encrypt_folder(folder_path, public_key):
    print(f"Encrypting folder: {folder_path}")
    files = glob.glob(os.path.join(folder_path, '**/*'), recursive=True)
    for file in files:
        if os.path.isfile(file):
            encrypt_file(file, public_key)

# Decrypt all files in a folder
def decrypt_folder(folder_path, private_key):
    print(f"Decrypting folder: {folder_path}")
    encrypted_files = glob.glob(os.path.join(folder_path, '**/*.enc'), recursive=True)
    for enc_file in encrypted_files:
        decrypt_file(enc_file, private_key)

# Main function to handle user input
def main():
    mode = input("Choose mode (encrypt/decrypt): ").lower()
    data_type = input("Enter the type of data (string/file/folder): ").lower()

    if mode == 'encrypt':
        public_key_path = input("Enter the public key path: ")
        public_key = load_key(public_key_path)
        
        if data_type == 'string':
            data = input("Enter the string to encrypt: ")
            encrypted_data = encrypt_string(data, public_key)
            print(f"Encrypted string: {encrypted_data.hex()}")
        elif data_type == 'file':
            file_path = input("Enter the file path to encrypt: ")
            encrypt_file(file_path, public_key)
            print(f"File encrypted and saved as: {file_path}.enc")
        elif data_type == 'folder':
            folder_path = input("Enter the folder path to encrypt: ")
            encrypt_folder(folder_path, public_key)
            print("Folder encrypted.")
        else:
            print("Invalid data type selected.")
    elif mode == 'decrypt':
        private_key_path = input("Enter the private key path: ")
        private_key = load_key(private_key_path)
        
        if data_type == 'string':
            encrypted_string = input("Enter the encrypted string (in hex): ")
            encrypted_data = bytes.fromhex(encrypted_string)
            decrypted_data = decrypt_string(encrypted_data, private_key)
            print(f"Decrypted string: {decrypted_data}")
        elif data_type == 'file':
            encrypted_file_path = input("Enter the encrypted file path: ")
            decrypt_file(encrypted_file_path, private_key)
        elif data_type == 'folder':
            folder_path = input("Enter the folder path to decrypt: ")
            decrypt_folder(folder_path, private_key)
            print("Folder decrypted.")
        else:
            print("Invalid data type selected.")
    else:
        print("Invalid mode selected.")

if __name__ == "__main__":
    private_key, public_key = generate_rsa_keypair()
    save_keys(private_key, public_key, "private.pem", "public.pem")
    print("RSA keys generated and saved as 'private.pem' and 'public.pem'")
    
    main()
