# Secure Data Encryption System with Error Fixes and Stable Key

import streamlit as st
import hashlib
import json
from cryptography.fernet import Fernet

# -------------------------------
# 🔐 Use a fixed Fernet Key
# In real life, save it in .env or config securely
# You can generate one once via: Fernet.generate_key()
KEY = b'DI2iL7I-1wnNBopkD0myeBdT9sF-8VzlyM20uKHzpjQ='
cipher = Fernet(KEY)

# -------------------------------
# In-Memory Data and Session
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {"username": {"encrypted_text":..., "passkey":...}}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "logged_in" not in st.session_state:
    st.session_state.logged_in = True

# -------------------------------
# Utility Functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(enc_text):
    try:
        return cipher.decrypt(enc_text.encode()).decode()
    except:
        return None

# -------------------------------
# Streamlit UI
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("🔍 Navigation", menu)

# -------------------------------
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Encrypt and store data securely with passkeys.")

# -------------------------------
elif choice == "Store Data":
    st.subheader("📦 Store Data")
    username = st.text_input("Username")
    plain_text = st.text_area("Enter data to encrypt")
    passkey = st.text_input("Create a passkey", type="password")

    if st.button("Encrypt & Save"):
        if username and plain_text and passkey:
            hashed_key = hash_passkey(passkey)
            encrypted = encrypt_data(plain_text)
            st.session_state.stored_data[username] = {
                "encrypted_text": encrypted,
                "passkey": hashed_key
            }
            st.success("✅ Data stored successfully for user: " + username)
        else:
            st.error("❗ Please fill all fields")

# -------------------------------
elif choice == "Retrieve Data":
    if not st.session_state.logged_in:
        st.warning("🔒 Please login first")
    else:
        st.subheader("🔓 Retrieve Data")
        username = st.text_input("Enter your username")
        passkey = st.text_input("Enter your passkey", type="password")

        if st.button("Decrypt"):
            if username and passkey:
                if username not in st.session_state.stored_data:
                    st.error("User not found.")
                else:
                    user_data = st.session_state.stored_data[username]
                    if hash_passkey(passkey) == user_data["passkey"]:
                        decrypted = decrypt_data(user_data["encrypted_text"])
                        if decrypted:
                            st.success(f"✅ Decrypted Data: {decrypted}")
                            st.session_state.failed_attempts = 0
                        else:
                            st.error("❗ Decryption failed")
                    else:
                        st.session_state.failed_attempts += 1
                        st.error(f"❌ Incorrect passkey. Attempts left: {3 - st.session_state.failed_attempts}")
                        if st.session_state.failed_attempts >= 3:
                            st.session_state.logged_in = False
                            st.warning("🔐 Too many failed attempts. Redirecting to login...")

# -------------------------------
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.logged_in = True
            st.success("✅ Logged in successfully. You may now retrieve data.")
        else:
            st.error("❌ Incorrect master password")
