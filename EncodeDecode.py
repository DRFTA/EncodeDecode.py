import streamlit as st
import base64
import hashlib
from cryptography.fernet import Fernet

# Function to derive a Fernet key from a password
def derive_key(password: str) -> bytes:
    """Derive a Fernet key from a password."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# Streamlit page setup
st.title("Text Encryptor")
st.write("Use the app to encrypt or decrypt text based on a password.")

# Password input field
password = st.text_input("Password", type="password")

# Text input box for the message to be encrypted/decrypted
text = st.text_area("Enter Text")

# Buttons for encryption and decryption
if st.button("Encrypt"):
    if password and text:
        try:
            key = derive_key(password)
            fernet = Fernet(key)
            encrypted = fernet.encrypt(text.encode()).decode()
            st.text_area("Encrypted Text", encrypted)
        except Exception as e:
            st.error(f"Error during encryption: {e}")
    else:
        st.warning("Please enter both text and a password.")

if st.button("Decrypt"):
    if password and text:
        try:
            key = derive_key(password)
            fernet = Fernet(key)
            decrypted = fernet.decrypt(text.encode()).decode()
            st.text_area("Decrypted Text", decrypted)
        except Exception as e:
            st.error(f"Error during decryption: {e}")
    else:
        st.warning("Please enter both text and a password.")
