import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import keyring
from pgpy import PGPKey, PGPMessage

def load_public_key_from_text(key_text):
    key, _ = PGPKey.from_blob(key_text)
    return key

def load_private_key_from_text(key_text, passphrase):
    key, _ = PGPKey.from_blob(key_text)
    if key.is_protected:
        key.unlock(passphrase)
    return key

def encrypt_message(public_key, message):
    pgp_msg = PGPMessage.new(message, cleartext=True)
    enc = public_key.encrypt(pgp_msg)
    return str(enc)

def decrypt_message(private_key, encrypted_message):
    pgp_msg = PGPMessage.from_blob(encrypted_message)
    dec = private_key.decrypt(pgp_msg)
    return dec.message

def store_key(key_type, key_text):
    keyring.set_password("pgp_app", key_type, key_text)

def get_stored_key(key_type):
    return keyring.get_password("pgp_app", key_type)

def load_public_key_file():
    path = filedialog.askopenfilename(filetypes=[("PGP Public Key Files", "*.asc *.pgp"), ("All files", "*.*")])
    if path:
        try:
            with open(path, "r") as f:
                key_text = f.read()
            store_key("public_key", key_text)
            public_key_text.delete("1.0", tk.END)
            public_key_text.insert(tk.END, key_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

def encrypt_action():
    try:
        key_text = get_stored_key("public_key")
        if not key_text:
            messagebox.showerror("Error", "Load a public key first.")
            return
        pubkey = load_public_key_from_text(key_text)
        message = plaintext_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Enter message to encrypt.")
            return
        enc_message = encrypt_message(pubkey, message)
        ciphertext_text.delete("1.0", tk.END)
        ciphertext_text.insert(tk.END, enc_message)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def copy_encrypted_text():
    root.clipboard_clear()
    root.clipboard_append(ciphertext_text.get("1.0", tk.END).strip())

def load_private_key_file():
    path = filedialog.askopenfilename(filetypes=[("PGP Private Key Files", "*.asc *.pgp"), ("All files", "*.*")])
    if path:
        try:
            with open(path, "r") as f:
                key_text = f.read()
            store_key("private_key", key_text)
            private_key_text.delete("1.0", tk.END)
            private_key_text.insert(tk.END, key_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

def decrypt_action():
    try:
        key_text = get_stored_key("private_key")
        if not key_text:
            messagebox.showerror("Error", "Load a private key first.")
            return
        passphrase = passphrase_entry.get()
        privkey = load_private_key_from_text(key_text, passphrase)
        encrypted_message = ciphertext_input.get("1.0", tk.END).strip()
        if not encrypted_message:
            messagebox.showerror("Error", "Enter message to decrypt.")
            return
        dec_message = decrypt_message(privkey, encrypted_message)
        decrypted_text.delete("1.0", tk.END)
        decrypted_text.insert(tk.END, dec_message)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def copy_decrypted_text():
    root.clipboard_clear()
    root.clipboard_append(decrypted_text.get("1.0", tk.END).strip())

root = tk.Tk()
root.title("PGP Encrypt/Decrypt")

nb = ttk.Notebook(root)
encrypt_frame = ttk.Frame(nb)
decrypt_frame = ttk.Frame(nb)
nb.add(encrypt_frame, text="Encrypt")
nb.add(decrypt_frame, text="Decrypt")
nb.pack(expand=1, fill="both")

pubkey_frame = ttk.LabelFrame(encrypt_frame, text="Public Key")
pubkey_frame.pack(fill="x", padx=5, pady=5)
public_key_text = scrolledtext.ScrolledText(pubkey_frame, height=10)
public_key_text.pack(fill="x", padx=5, pady=5)
load_pub_key_btn = ttk.Button(pubkey_frame, text="Load Public Key", command=load_public_key_file)
load_pub_key_btn.pack(padx=5, pady=5)

plaintext_frame = ttk.LabelFrame(encrypt_frame, text="Plaintext Message")
plaintext_frame.pack(fill="both", expand=True, padx=5, pady=5)
plaintext_text = scrolledtext.ScrolledText(plaintext_frame, height=10)
plaintext_text.pack(fill="both", expand=True, padx=5, pady=5)

enc_btn = ttk.Button(encrypt_frame, text="Encrypt", command=encrypt_action)
enc_btn.pack(padx=5, pady=5)

ciphertext_frame = ttk.LabelFrame(encrypt_frame, text="Encrypted Message")
ciphertext_frame.pack(fill="both", expand=True, padx=5, pady=5)
ciphertext_text = scrolledtext.ScrolledText(ciphertext_frame, height=10)
ciphertext_text.pack(fill="both", expand=True, padx=5, pady=5)
copy_enc_btn = ttk.Button(encrypt_frame, text="Copy Encrypted Message", command=copy_encrypted_text)
copy_enc_btn.pack(padx=5, pady=5)

privkey_frame = ttk.LabelFrame(decrypt_frame, text="Private Key")
privkey_frame.pack(fill="x", padx=5, pady=5)
private_key_text = scrolledtext.ScrolledText(privkey_frame, height=10)
private_key_text.pack(fill="x", padx=5, pady=5)
load_priv_key_btn = ttk.Button(privkey_frame, text="Load Private Key", command=load_private_key_file)
load_priv_key_btn.pack(padx=5, pady=5)

passphrase_frame = ttk.LabelFrame(decrypt_frame, text="Passphrase")
passphrase_frame.pack(fill="x", padx=5, pady=5)
passphrase_entry = ttk.Entry(passphrase_frame, show="*")
passphrase_entry.pack(fill="x", padx=5, pady=5)

ciphertext_input_frame = ttk.LabelFrame(decrypt_frame, text="Encrypted Message")
ciphertext_input_frame.pack(fill="both", expand=True, padx=5, pady=5)
ciphertext_input = scrolledtext.ScrolledText(ciphertext_input_frame, height=10)
ciphertext_input.pack(fill="both", expand=True, padx=5, pady=5)

dec_btn = ttk.Button(decrypt_frame, text="Decrypt", command=decrypt_action)
dec_btn.pack(padx=5, pady=5)

decrypted_frame = ttk.LabelFrame(decrypt_frame, text="Decrypted Message")
decrypted_frame.pack(fill="both", expand=True, padx=5, pady=5)
decrypted_text = scrolledtext.ScrolledText(decrypted_frame, height=10)
decrypted_text.pack(fill="both", expand=True, padx=5, pady=5)
copy_dec_btn = ttk.Button(decrypt_frame, text="Copy Decrypted Message", command=copy_decrypted_text)
copy_dec_btn.pack(padx=5, pady=5)

root.mainloop()