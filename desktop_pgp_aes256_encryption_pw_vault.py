import os
import base64
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog as sd
import keyring
from pgpy import PGPKey, PGPMessage
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import hashlib
import threading

salt = b'my_app_master_salt'
aes_secret_key = None
master_password = None
fernet = None

def derive_master_key(pw):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(pw.encode()))

def derive_aes_key(pw):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    return kdf.derive(pw.encode())

def aes_encrypt(pw, data):
    key = derive_aes_key(pw)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(iv + ct).decode()

def aes_decrypt(pw, token):
    raw = base64.b64decode(token)
    iv, ct = raw[:16], raw[16:]
    key = derive_aes_key(pw)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()
    return data.decode()

def store_master_hash(pw):
    keyring.set_password("pgp_app", "master_pw_hash", hashlib.sha256(pw.encode()).hexdigest())

def verify_master_password(pw):
    global fernet
    stored = keyring.get_password("pgp_app", "master_pw_hash")
    if not stored:
        return False
    if hashlib.sha256(pw.encode()).hexdigest() != stored:
        return False
    fernet = Fernet(derive_master_key(pw))
    return True

def setup_master_password():
    pw = sd.askstring("Set Master Password", "Set a master password:", show="*")
    if not pw:
        exit()
    global fernet, master_password
    fernet = Fernet(derive_master_key(pw))
    master_password = pw
    store_master_hash(pw)

def change_master_password():
    global fernet, master_password
    cur = sd.askstring("Current Master Password", "Enter current master password:", show="*")
    if not cur or not verify_master_password(cur):
        messagebox.showerror("Error", "Invalid current password")
        return
    new = sd.askstring("New Master Password", "Enter new master password:", show="*")
    if not new:
        return
    confirm = sd.askstring("Confirm Password", "Confirm new master password:", show="*")
    if new != confirm:
        messagebox.showerror("Error", "Passwords do not match")
        return
    old = fernet
    new_fernet = Fernet(derive_master_key(new))
    for kt in ("private_key", "sign_private_key", "credentials"):
        data = keyring.get_password("pgp_app", kt)
        if data:
            dec = old.decrypt(data.encode())
            keyring.set_password("pgp_app", kt, new_fernet.encrypt(dec).decode())
    fernet = new_fernet
    store_master_hash(new)
    master_password = new
    messagebox.showinfo("Success", "Master password changed")

def load_public_key_from_text(txt):
    key, _ = PGPKey.from_blob(txt)
    return key

def load_private_key_from_text(txt):
    key, _ = PGPKey.from_blob(txt)
    return key

def encrypt_message(pub, msg):
    return str(pub.encrypt(PGPMessage.new(msg)))

def decrypt_message(priv, ct, pp):
    m = PGPMessage.from_blob(ct)
    with priv.unlock(pp):
        return priv.decrypt(m).message

def sign_message_detached(priv, msg, pp):
    pmsg = PGPMessage.new(msg, cleartext=False)
    with priv.unlock(pp):
        return priv.sign(pmsg, detached=True)

def verify_signature(pub, sm):
    m = PGPMessage.from_blob(sm)
    return bool(pub.verify(m)), m.message or ""

def store_key(kt, txt):
    if kt in ("private_key", "sign_private_key", "credentials"):
        enc = fernet.encrypt(txt.encode()).decode()
        keyring.set_password("pgp_app", kt, enc)
    else:
        keyring.set_password("pgp_app", kt, txt)

def get_stored_key(kt):
    d = keyring.get_password("pgp_app", kt)
    if not d:
        return None
    if kt in ("private_key", "sign_private_key", "credentials"):
        try:
            return fernet.decrypt(d.encode()).decode()
        except:
            return None
    return d

def load_credentials():
    data = keyring.get_password("pgp_app", "credentials")
    if not data:
        return {}
    try:
        dec = fernet.decrypt(data.encode()).decode()
        return json.loads(dec)
    except:
        return {}

def save_credentials(creds):
    enc = fernet.encrypt(json.dumps(creds).encode()).decode()
    keyring.set_password("pgp_app", "credentials", enc)

def encrypt_action():
    key = load_public_key_from_text(public_key_text.get("1.0", tk.END).strip())
    ct = encrypt_message(key, plaintext_text.get("1.0", tk.END))
    ciphertext_text.delete("1.0", tk.END)
    ciphertext_text.insert(tk.END, ct)

def decrypt_action():
    key_text = private_key_text.get("1.0", tk.END).strip()
    ct_blob = ciphertext_input.get("1.0", tk.END).strip()
    pw = passphrase_entry.get()
    def worker(k_txt, ctb, pw_):
        try:
            priv = load_private_key_from_text(k_txt)
            pt = decrypt_message(priv, ctb, pw_)
            root.after(0, lambda: (decrypted_text.delete("1.0", tk.END), decrypted_text.insert(tk.END, pt)))
        except Exception as e:
            root.after(0, lambda: messagebox.showerror("Error", str(e)))
    threading.Thread(target=worker, args=(key_text, ct_blob, pw), daemon=True).start()

def sign_action():
    key = load_private_key_from_text(private_sign_key_text.get("1.0", tk.END).strip())
    msg = sign_input_text.get("1.0", tk.END).rstrip('\n')
    signature = sign_message_detached(key, msg, passphrase_sign_entry.get())
    header = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n"
    signed = header + msg + "\n" + str(signature)
    signature_text.delete("1.0", tk.END)
    signature_text.insert(tk.END, signed)

def sign_file_action():
    path = filedialog.askopenfilename(title="Select file to sign")
    if not path:
        return
    with open(path, "r") as f:
        content = f.read()
    key = load_private_key_from_text(private_sign_key_text.get("1.0", tk.END).strip())
    sig = sign_message_detached(key, content, passphrase_sign_entry.get())
    sig_path = path + ".sig"
    with open(sig_path, "w") as f:
        f.write(str(sig))
    messagebox.showinfo("Signed", f"Signature saved to {sig_path}")

def verify_action():
    pub = load_public_key_from_text(public_verify_key_text.get("1.0", tk.END).strip())
    sm_blob = verify_input_text.get("1.0", tk.END).strip()
    if not sm_blob:
        messagebox.showerror("Error", "No signed message")
        return
    try:
        valid, orig = verify_signature(pub, sm_blob)
    except TypeError:
        path = filedialog.askopenfilename(title="Select original message file", filetypes=[("Text Files","*.txt"),("All Files","*.*")])
        if not path:
            return
        with open(path, "r") as f:
            orig = f.read()
        sig = PGPMessage.from_blob(sm_blob)
        clear = PGPMessage.new(orig, cleartext=True)
        result = pub.verify(clear, signature=sig)
        valid = all(s.valid for s in result) if hasattr(result, '__iter__') else bool(result)
    verify_output_text.delete("1.0", tk.END)
    verify_output_text.insert(tk.END, f"Valid: {valid}\n\n{orig}")

def load_key_file(kt, w):
    p = filedialog.askopenfilename(filetypes=[("PGP Key Files", "*.asc *.pgp"), ("All files", "*.*")])
    if p:
        with open(p, "r") as f:
            txt = f.read()
        store_key(kt, txt)
        w.delete("1.0", tk.END)
        w.insert(tk.END, txt)

def copy_to_clipboard(w):
    root.clipboard_clear()
    root.clipboard_append(w.get("1.0", tk.END).strip())

def save_aes_ciphertext_action():
    ct = aes_ciphertext_text.get("1.0", tk.END).strip()
    if not ct:
        messagebox.showerror("Error", "No ciphertext")
        return
    path = os.path.join(os.path.expanduser("~/Downloads"), "aes256_ciphertext.txt")
    try:
        with open(path, "w") as f:
            f.write(ct)
        messagebox.showinfo("Saved", f"Ciphertext saved to {path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def export_public_key(kt):
    txt = get_stored_key(kt)
    if not txt:
        messagebox.showerror("Error", "No key stored")
        return
    path = filedialog.asksaveasfilename(defaultextension=".asc", filetypes=[("PGP Public Key","*.asc"),("All Files","*.*")])
    if path:
        with open(path, "w") as f:
            f.write(txt)
        messagebox.showinfo("Export", f"Public key saved to {path}")

def export_private_key(kt):
    pw = sd.askstring("Password", "Enter master password:", show="*")
    if not pw or not verify_master_password(pw):
        messagebox.showerror("Error", "Invalid password")
        return
    txt = get_stored_key(kt)
    if not txt:
        messagebox.showerror("Error", "No key stored")
        return
    path = filedialog.asksaveasfilename(defaultextension=".asc", filetypes=[("PGP Private Key","*.asc"),("All Files","*.*")])
    if path:
        with open(path, "w") as f:
            f.write(txt)
        messagebox.showinfo("Export", f"Private key saved to {path}")

def save_encrypted_action():
    ct = ciphertext_text.get("1.0", tk.END).strip()
    if not ct:
        messagebox.showerror("Error", "No ciphertext")
        return
    path = filedialog.asksaveasfilename(defaultextension=".pgp", filetypes=[("PGP Files","*.pgp"),("All Files","*.*")])
    if path:
        with open(path, "w") as f:
            f.write(ct)
        messagebox.showinfo("Saved", f"Encrypted message saved to {path}")

def save_decrypted_action():
    pt = decrypted_text.get("1.0", tk.END)
    if not pt.strip():
        messagebox.showerror("Error", "No decrypted text")
        return
    path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files","*.txt"),("All Files","*.*")])
    if path:
        with open(path, "w") as f:
            f.write(pt)
        messagebox.showinfo("Saved", f"Decrypted message saved to {path}")

def set_unique_aes():
    global aes_secret_key
    key = sd.askstring("AES Key", "Enter unique AES key\n(leave blank to use master password):", show="*")
    if key:
        aes_secret_key = key
        aes_mode_label.config(text="AES mode: Unique Key")
    else:
        aes_secret_key = None
        aes_mode_label.config(text="AES mode: Master Password")

def use_master_aes():
    global aes_secret_key
    aes_secret_key = None
    aes_mode_label.config(text="AES mode: Master Password")

def aes_encrypt_action():
    pw = aes_secret_key if aes_secret_key else master_password
    ct = aes_encrypt(pw, aes_plaintext_text.get("1.0", tk.END))
    aes_ciphertext_text.delete("1.0", tk.END)
    aes_ciphertext_text.insert(tk.END, ct)

def aes_decrypt_action():
    pw = aes_secret_key if aes_secret_key else master_password
    token = aes_ciphertext_text.get("1.0", tk.END).strip()
    try:
        pt = aes_decrypt(pw, token)
        aes_decrypted_text.delete("1.0", tk.END)
        aes_decrypted_text.insert(tk.END, pt)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def aes_encrypt_file_action():
    pw = aes_secret_key if aes_secret_key else master_password
    path = filedialog.askopenfilename(title="Select file to encrypt")
    if not path:
        return
    with open(path, "rb") as f:
        data = f.read()
    key = derive_aes_key(pw)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    out_path = path + ".aes256"
    with open(out_path, "wb") as f:
        f.write(iv + ct)
    messagebox.showinfo("Encrypted", f"File encrypted to {out_path}")

def aes_decrypt_file_action():
    pw = aes_secret_key if aes_secret_key else master_password
    path = filedialog.askopenfilename(title="Select .aes256 file to decrypt", filetypes=[("AES256 Files","*.aes256"),("All Files","*.*")])
    if not path:
        return
    with open(path, "rb") as f:
        raw = f.read()
    iv, ct = raw[:16], raw[16:]
    key = derive_aes_key(pw)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()
    out_path = path[:-7] if path.endswith(".aes256") else path + ".dec"
    with open(out_path, "wb") as f:
        f.write(data)
    messagebox.showinfo("Decrypted", f"File decrypted to {out_path}")

def add_cred():
    site = sd.askstring("Site", "Enter site:")
    if not site:
        return
    username = sd.askstring("Username", "Enter username:")
    if username is None:
        return
    password = sd.askstring("Password", "Enter password:", show="*")
    if password is None:
        return
    creds = load_credentials()
    creds[site] = {"username": username, "password": password}
    save_credentials(creds)
    refresh_credentials_view()

def edit_cred():
    sel = tree.selection()
    if not sel:
        return
    site = sel[0]
    creds = load_credentials()
    info = creds.get(site, {})
    new_user = sd.askstring("Username", "Edit username:", initialvalue=info.get("username",""))
    if new_user is None:
        return
    new_pass = sd.askstring("Password", "Edit password:", show="*", initialvalue=info.get("password",""))
    if new_pass is None:
        return
    creds[site] = {"username": new_user, "password": new_pass}
    save_credentials(creds)
    refresh_credentials_view()

def delete_cred():
    sel = tree.selection()
    if not sel:
        return
    site = sel[0]
    creds = load_credentials()
    creds.pop(site, None)
    save_credentials(creds)
    refresh_credentials_view()

def show_password():
    sel = tree.selection()
    if not sel:
        return
    site = sel[0]
    creds = load_credentials()
    pwd = creds.get(site, {}).get("password", "")
    messagebox.showinfo("Password", f"{site}: {pwd}")

def copy_selected(field):
    sel = tree.selection()
    if not sel:
        return
    site = sel[0]
    creds = load_credentials()
    val = creds.get(site, {}).get(field, "")
    root.clipboard_clear()
    root.clipboard_append(val)

if not keyring.get_password("pgp_app", "master_pw_hash"):
    setup_master_password()
else:
    while True:
        master_password = sd.askstring("Master Password", "Enter master password:", show="*")
        if not master_password:
            exit()
        if verify_master_password(master_password):
            break
        messagebox.showerror("Invalid", "Invalid master password")

root = tk.Tk()
root.title("PDFSage PGP & AES & PW Vault Tool")
menubar = tk.Menu(root)
acct = tk.Menu(menubar, tearoff=0)
acct.add_command(label="Change Master Password", command=change_master_password)
menubar.add_cascade(label="Account", menu=acct)
keys_menu = tk.Menu(menubar, tearoff=0)
keys_menu.add_command(label="Save Encryption Public Key", command=lambda: store_key("public_key", public_key_text.get("1.0", tk.END).strip()) or messagebox.showinfo("Saved", "Public key stored"))
keys_menu.add_command(label="Save Encryption Private Key", command=lambda: store_key("private_key", private_key_text.get("1.0", tk.END).strip()) or messagebox.showinfo("Saved", "Private key stored"))
keys_menu.add_command(label="Save Signing Private Key", command=lambda: store_key("sign_private_key", private_sign_key_text.get("1.0", tk.END).strip()) or messagebox.showinfo("Saved", "Signing key stored"))
keys_menu.add_command(label="Save Verify Public Key", command=lambda: store_key("verify_public_key", public_verify_key_text.get("1.0", tk.END).strip()) or messagebox.showinfo("Saved", "Verify public key stored"))
menubar.add_cascade(label="Keys", menu=keys_menu)
root.config(menu=menubar)
nb = ttk.Notebook(root)
encrypt_frame = ttk.Frame(nb)
decrypt_frame = ttk.Frame(nb)
sign_frame = ttk.Frame(nb)
verify_frame = ttk.Frame(nb)
aes_frame = ttk.Frame(nb)
nb.add(encrypt_frame, text="Encrypt")
nb.add(decrypt_frame, text="Decrypt")
nb.add(sign_frame, text="Sign")
nb.add(verify_frame, text="Verify")
nb.add(aes_frame, text="AES256")
nb.pack(expand=1, fill="both")
pub_frame = ttk.LabelFrame(encrypt_frame, text="Public Key")
pub_frame.pack(fill="x", padx=5, pady=5)
public_key_text = scrolledtext.ScrolledText(pub_frame, height=10)
public_key_text.pack(fill="x", padx=5, pady=5)
stored = get_stored_key("public_key")
if stored:
    public_key_text.insert("1.0", stored)
ttk.Button(pub_frame, text="Load Public Key", command=lambda: load_key_file("public_key", public_key_text)).pack(padx=5, pady=5)
ttk.Button(pub_frame, text="Export Public Key", command=lambda: export_public_key("public_key")).pack(padx=5, pady=5)
pt_frame = ttk.LabelFrame(encrypt_frame, text="Plaintext")
pt_frame.pack(fill="both", expand=True, padx=5, pady=5)
plaintext_text = scrolledtext.ScrolledText(pt_frame, height=10)
plaintext_text.pack(fill="both", expand=True, padx=5, pady=5)
ttk.Button(encrypt_frame, text="Encrypt", command=encrypt_action).pack(padx=5, pady=5)
ct_frame = ttk.LabelFrame(encrypt_frame, text="Ciphertext")
ct_frame.pack(fill="both", expand=True, padx=5, pady=5)
ciphertext_text = scrolledtext.ScrolledText(ct_frame, height=10)
ciphertext_text.pack(fill="both", expand=True, padx=5, pady=5)
ttk.Button(encrypt_frame, text="Copy Encrypted", command=lambda: copy_to_clipboard(ciphertext_text)).pack(padx=5, pady=5)
ttk.Button(encrypt_frame, text="Save Encrypted", command=save_encrypted_action).pack(padx=5, pady=5)
priv_frame = ttk.LabelFrame(decrypt_frame, text="Private Key")
priv_frame.pack(fill="x", padx=5, pady=5)
private_key_text = scrolledtext.ScrolledText(priv_frame, height=10)
private_key_text.pack(fill="x", padx=5, pady=5)
stored_priv = get_stored_key("private_key")
if stored_priv:
    private_key_text.insert("1.0", stored_priv)
ttk.Button(priv_frame, text="Load Private Key", command=lambda: load_key_file("private_key", private_key_text)).pack(padx=5, pady=5)
ttk.Button(priv_frame, text="Export Private Key", command=lambda: export_private_key("private_key")).pack(padx=5, pady=5)
pp_frame = ttk.LabelFrame(decrypt_frame, text="Passphrase")
pp_frame.pack(fill="x", padx=5, pady=5)
passphrase_entry = ttk.Entry(pp_frame, show="*")
passphrase_entry.pack(fill="x", padx=5, pady=5)
dec_in_frame = ttk.LabelFrame(decrypt_frame, text="Ciphertext")
dec_in_frame.pack(fill="both", expand=True, padx=5, pady=5)
ciphertext_input = scrolledtext.ScrolledText(dec_in_frame, height=10)
ciphertext_input.pack(fill="both", expand=True, padx=5, pady=5)
ttk.Button(decrypt_frame, text="Decrypt", command=decrypt_action).pack(padx=5, pady=5)
dec_out_frame = ttk.LabelFrame(decrypt_frame, text="Plaintext")
dec_out_frame.pack(fill="both", expand=True, padx=5, pady=5)
decrypted_text = scrolledtext.ScrolledText(dec_out_frame, height=10)
decrypted_text.pack(fill="both", expand=True, padx=5, pady=5)
ttk.Button(decrypt_frame, text="Copy Decrypted", command=lambda: copy_to_clipboard(decrypted_text)).pack(padx=5, pady=5)
ttk.Button(decrypt_frame, text="Save Decrypted", command=save_decrypted_action).pack(padx=5, pady=5)
spriv_frame = ttk.LabelFrame(sign_frame, text="Private Key")
spriv_frame.pack(fill="x", padx=5, pady=5)
private_sign_key_text = scrolledtext.ScrolledText(spriv_frame, height=10)
private_sign_key_text.pack(fill="x", padx=5, pady=5)
stored_sign = get_stored_key("sign_private_key")
if stored_sign:
    private_sign_key_text.insert("1.0", stored_sign)
ttk.Button(spriv_frame, text="Load Private Key", command=lambda: load_key_file("sign_private_key", private_sign_key_text)).pack(padx=5, pady=5)
ttk.Button(spriv_frame, text="Export Private Key", command=lambda: export_private_key("sign_private_key")).pack(padx=5, pady=5)
spp_frame = ttk.LabelFrame(sign_frame, text="Passphrase")
spp_frame.pack(fill="x", padx=5, pady=5)
passphrase_sign_entry = ttk.Entry(spp_frame, show="*")
passphrase_sign_entry.pack(fill="x", padx=5, pady=5)
sin_frame = ttk.LabelFrame(sign_frame, text="Message")
sin_frame.pack(fill="both", expand=True, padx=5, pady=5)
sign_input_text = scrolledtext.ScrolledText(sin_frame, height=10)
sign_input_text.pack(fill="both", expand=True, padx=5, pady=5)
ttk.Button(sign_frame, text="Sign", command=sign_action).pack(side="left", padx=5, pady=5)
ttk.Button(sign_frame, text="Sign File", command=sign_file_action).pack(side="left", padx=5, pady=5)
sout_frame = ttk.LabelFrame(sign_frame, text="Signed Message")
sout_frame.pack(fill="both", expand=True, padx=5, pady=5)
signature_text = scrolledtext.ScrolledText(sout_frame, height=10)
signature_text.pack(fill="both", expand=True, padx=5, pady=5)
ttk.Button(sign_frame, text="Copy Signature", command=lambda: copy_to_clipboard(signature_text)).pack(padx=5, pady=5)
vpub_frame = ttk.LabelFrame(verify_frame, text="Public Key")
vpub_frame.pack(fill="x", padx=5, pady=5)
public_verify_key_text = scrolledtext.ScrolledText(vpub_frame, height=10)
public_verify_key_text.pack(fill="x", padx=5, pady=5)
stored_ver = get_stored_key("verify_public_key")
if stored_ver:
    public_verify_key_text.insert("1.0", stored_ver)
ttk.Button(vpub_frame, text="Load Public Key", command=lambda: load_key_file("verify_public_key", public_verify_key_text)).pack(padx=5, pady=5)
ttk.Button(vpub_frame, text="Export Public Key", command=lambda: export_public_key("verify_public_key")).pack(padx=5, pady=5)
vin_frame = ttk.LabelFrame(verify_frame, text="Signed Message")
vin_frame.pack(fill="both", expand=True, padx=5, pady=5)
verify_input_text = scrolledtext.ScrolledText(vin_frame, height=10)
verify_input_text.pack(fill="both", expand=True, padx=5, pady=5)
ttk.Button(verify_frame, text="Verify", command=verify_action).pack(padx=5, pady=5)
vout_frame = ttk.LabelFrame(verify_frame, text="Original Message")
vout_frame.pack(fill="both", expand=True, padx=5, pady=5)
verify_output_text = scrolledtext.ScrolledText(vout_frame, height=10)
verify_output_text.pack(fill="both", expand=True, padx=5, pady=5)
pas_frame = ttk.LabelFrame(aes_frame, text="AES Mode")
pas_frame.pack(fill="x", padx=5, pady=5)
aes_mode_label = ttk.Label(pas_frame, text="AES mode: Master Password")
aes_mode_label.pack(side="left", padx=5, pady=5)
ttk.Button(pas_frame, text="Set AES Key", command=set_unique_aes).pack(side="left", padx=5, pady=5)
ttk.Button(pas_frame, text="Use Master Password", command=use_master_aes).pack(side="left", padx=5, pady=5)
plain_frame = ttk.LabelFrame(aes_frame, text="Plaintext")
plain_frame.pack(fill="both", expand=True, padx=5, pady=5)
aes_plaintext_text = scrolledtext.ScrolledText(plain_frame, height=10)
aes_plaintext_text.pack(fill="both", expand=True, padx=5, pady=5)
ttk.Button(aes_frame, text="Encrypt", command=aes_encrypt_action).pack(side="left", padx=5, pady=5)
cipher_frame = ttk.LabelFrame(aes_frame, text="Ciphertext")
cipher_frame.pack(fill="both", expand=True, padx=5, pady=5)
aes_ciphertext_text = scrolledtext.ScrolledText(cipher_frame, height=10)
aes_ciphertext_text.pack(fill="both", expand=True, padx=5, pady=5)
ttk.Button(aes_frame, text="Decrypt", command=aes_decrypt_action).pack(side="left", padx=5, pady=5)
ttk.Button(aes_frame, text="Encrypt File", command=aes_encrypt_file_action).pack(side="left", padx=5, pady=5)
ttk.Button(aes_frame, text="Decrypt File", command=aes_decrypt_file_action).pack(side="left", padx=5, pady=5)
ttk.Button(aes_frame, text="Copy Ciphertext", command=lambda: copy_to_clipboard(aes_ciphertext_text)).pack(side="left", padx=5, pady=5)
ttk.Button(aes_frame, text="Save Ciphertext", command=save_aes_ciphertext_action).pack(side="left", padx=5, pady=5)
dec_frame = ttk.LabelFrame(aes_frame, text="Decrypted")
dec_frame.pack(fill="both", expand=True, padx=5, pady=5)
aes_decrypted_text = scrolledtext.ScrolledText(dec_frame, height=10)
aes_decrypted_text.pack(fill="both", expand=True, padx=5, pady=5)
cred_frame = ttk.Frame(nb)
nb.add(cred_frame, text="Credentials")
columns = ("site", "username", "password")
tree = ttk.Treeview(cred_frame, columns=columns, show="headings")
for col in columns:
    tree.heading(col, text=col.capitalize())
tree.pack(fill="both", expand=True, padx=5, pady=5)
button_frame = ttk.Frame(cred_frame)
button_frame.pack(fill="x", padx=5, pady=5)
ttk.Button(button_frame, text="Add", command=add_cred).pack(side="left")
ttk.Button(button_frame, text="Edit", command=edit_cred).pack(side="left")
ttk.Button(button_frame, text="Delete", command=delete_cred).pack(side="left")
ttk.Button(button_frame, text="Show", command=show_password).pack(side="left")
ttk.Button(button_frame, text="Copy Password", command=lambda: copy_selected("password")).pack(side="left")
ttk.Button(button_frame, text="Copy Username", command=lambda: copy_selected("username")).pack(side="left")

def refresh_credentials_view():
    for i in tree.get_children():
        tree.delete(i)
    for site, info in load_credentials().items():
        tree.insert("", "end", iid=site, values=(site, info["username"], "******"))

refresh_credentials_view()

def on_close():
    global master_password, fernet, aes_secret_key
    master_password = None
    fernet = None
    aes_secret_key = None
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_close)

try:
    root.mainloop()
finally:
    master_password = None
    fernet = None
    aes_secret_key = None