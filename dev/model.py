# Importing the necessary modules to verify installation

# Import from the cryptography library
try:
    from cryptography.fernet import Fernet
    print("cryptography library is installed and working correctly.")
except ImportError:
    print("cryptography library is not installed correctly.")

# Import from the pycryptodome library
try:
    from Crypto.Cipher import AES
    print("pycryptodome library is installed and working correctly.")
except ImportError:
    print("pycryptodome library is not installed correctly.")
