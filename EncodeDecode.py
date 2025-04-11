import tkinter as tk
from tkinter import messagebox, scrolledtext
import base64
import hashlib
from cryptography.fernet import Fernet


def derive_key(password: str) -> bytes:
    """Derive a Fernet key from a password."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())


def encrypt_text():
    password = password_entry.get()
    text = text_box.get("1.0", tk.END).strip()
    if not password or not text:
        messagebox.showwarning("Missing Info", "Please enter both text and password.")
        return
    try:
        key = derive_key(password)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(text.encode()).decode()
        text_box.delete("1.0", tk.END)
        text_box.insert(tk.END, encrypted)
    except Exception as e:
        messagebox.showerror("Error", str(e))


def decrypt_text():
    password = password_entry.get()
    text = text_box.get("1.0", tk.END).strip()
    if not password or not text:
        messagebox.showwarning("Missing Info", "Please enter both text and password.")
        return
    try:
        key = derive_key(password)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(text.encode()).decode()
        text_box.delete("1.0", tk.END)
        text_box.insert(tk.END, decrypted)
    except Exception as e:
        messagebox.showerror("Error", "Decryption failed: " + str(e))


# GUI Setup
window = tk.Tk()
window.title("Text Encryptor")
window.geometry("500x400")
window.resizable(False, False)

# Password entry
tk.Label(window, text="Password:").pack(pady=(10, 0))
password_entry = tk.Entry(window, show="*", width=40)
password_entry.pack(pady=5)

# Text area
tk.Label(window, text="Text:").pack()
text_box = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=60, height=15)
text_box.pack(pady=5)

# Buttons
button_frame = tk.Frame(window)
button_frame.pack(pady=10)

encrypt_btn = tk.Button(button_frame, text="Encrypt", command=encrypt_text, width=15)
encrypt_btn.pack(side=tk.LEFT, padx=10)

decrypt_btn = tk.Button(button_frame, text="Decrypt", command=decrypt_text, width=15)
decrypt_btn.pack(side=tk.LEFT, padx=10)

window.mainloop()
