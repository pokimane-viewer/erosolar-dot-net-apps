import os
import base64
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog as sd
import keyring
from keyring.errors import PasswordDeleteError
from pgpy import PGPKey, PGPMessage, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
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
ACCOUNT_ID = None


def pref(k):
    return f'{ACCOUNT_ID}_{k}'


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


def load_accounts():
    data = keyring.get_password('pgp_app', 'accounts')
    if not data:
        return {}
    try:
        return json.loads(data)
    except Exception:
        return {}


def save_accounts(accts):
    keyring.set_password('pgp_app', 'accounts', json.dumps(accts))


def store_master_hash(pw):
    keyring.set_password('pgp_app', pref('master_pw_hash'), hashlib.sha256(pw.encode()).hexdigest())


def verify_master_password(pw):
    global fernet
    stored = keyring.get_password('pgp_app', pref('master_pw_hash'))
    if not stored:
        return False
    if hashlib.sha256(pw.encode()).hexdigest() != stored:
        return False
    fernet = Fernet(derive_master_key(pw))
    return True


def store_key(kt, txt):
    if kt in ('private_key', 'sign_private_key', 'credentials', 'pgp_keyvault'):
        enc = fernet.encrypt(txt.encode()).decode()
        keyring.set_password('pgp_app', pref(kt), enc)
    else:
        keyring.set_password('pgp_app', pref(kt), txt)


def get_stored_key(kt):
    d = keyring.get_password('pgp_app', pref(kt))
    if not d:
        return None
    if kt in ('private_key', 'sign_private_key', 'credentials', 'pgp_keyvault'):
        try:
            return fernet.decrypt(d.encode()).decode()
        except Exception:
            return None
    return d


def load_credentials():
    data = keyring.get_password('pgp_app', pref('credentials'))
    if not data:
        return {}
    try:
        dec = fernet.decrypt(data.encode()).decode()
        return json.loads(dec)
    except Exception:
        return {}


def save_credentials(creds):
    enc = fernet.encrypt(json.dumps(creds).encode()).decode()
    keyring.set_password('pgp_app', pref('credentials'), enc)


def load_keyvault():
    data = keyring.get_password('pgp_app', pref('pgp_keyvault'))
    if not data:
        return {}
    try:
        dec = fernet.decrypt(data.encode()).decode()
        return json.loads(dec)
    except Exception:
        return {}


def save_keyvault(vault):
    enc = fernet.encrypt(json.dumps(vault).encode()).decode()
    keyring.set_password('pgp_app', pref('pgp_keyvault'), enc)


def delete_account_data(email):
    for kt in ('private_key', 'sign_private_key', 'credentials', 'pgp_keyvault',
               'public_key', 'verify_public_key', 'master_pw_hash'):
        try:
            keyring.delete_password('pgp_app', f'{email}_{kt}')
        except PasswordDeleteError:
            pass
    accts = load_accounts()
    was_default = accts.get(email, {}).get('default')
    accts.pop(email, None)
    if was_default and accts:
        first = next(iter(accts))
        for v in accts.values():
            v['default'] = False
        accts[first]['default'] = True
    save_accounts(accts)


def change_master_password():
    global fernet, master_password
    cur = sd.askstring('Current Master Password', 'Enter current master password:', show='*')
    if not cur or not verify_master_password(cur):
        messagebox.showerror('Error', 'Invalid current password')
        return
    new = sd.askstring('New Master Password', 'Enter new master password:', show='*')
    if not new:
        return
    confirm = sd.askstring('Confirm Password', 'Confirm new master password:', show='*')
    if new != confirm:
        messagebox.showerror('Error', 'Passwords do not match')
        return
    old = fernet
    new_fernet = Fernet(derive_master_key(new))
    for kt in ('private_key', 'sign_private_key', 'credentials', 'pgp_keyvault'):
        data = keyring.get_password('pgp_app', pref(kt))
        if data:
            dec = old.decrypt(data.encode())
            keyring.set_password('pgp_app', pref(kt), new_fernet.encrypt(dec).decode())
    fernet = new_fernet
    store_master_hash(new)
    master_password = new
    messagebox.showinfo('Success', 'Master password changed')


def delete_account():
    pw = sd.askstring('Password', 'Enter master password to confirm deletion:', show='*')
    if not pw or not verify_master_password(pw):
        messagebox.showerror('Error', 'Invalid password')
        return
    if not messagebox.askyesno('Confirm', 'Delete this account? This cannot be undone.'):
        return
    delete_account_data(ACCOUNT_ID)
    messagebox.showinfo('Deleted', 'Account deleted. Application will close.')
    on_close()


def create_new_account():
    global ACCOUNT_ID, master_password, fernet
    name = sd.askstring('Name', 'Enter full name:')
    if not name:
        return False
    email = sd.askstring('Email', 'Enter email address:')
    if not email:
        return False
    while True:
        pw = sd.askstring('Master Password', 'Set a master password:', show='*')
        if not pw:
            return False
        confirm = sd.askstring('Confirm', 'Confirm master password:', show='*')
        if pw != confirm:
            messagebox.showerror('Error', 'Passwords do not match')
        else:
            break
    accts = load_accounts()
    if email in accts:
        messagebox.showerror('Error', 'Account already exists')
        return False
    is_def = not any(v.get('default') for v in accts.values())
    accts[email] = {'name': name, 'default': is_def}
    save_accounts(accts)
    ACCOUNT_ID = email
    master_password = pw
    fernet = Fernet(derive_master_key(pw))
    store_master_hash(pw)
    return True


def account_selection_gui(accounts):
    result = {'choice': None, 'action': None}
    win = tk.Tk()
    win.title('Select Account')
    tree = ttk.Treeview(win, columns=('acc',), show='headings', height=10)
    tree.heading('acc', text='Account')
    for email, info in accounts.items():
        display = f"{'★ ' if info.get('default') else ''}{email} ({info.get('name', '')})"
        tree.insert('', 'end', iid=email, values=(display,))
    for email, info in accounts.items():
        if info.get('default'):
            tree.selection_set(email)
            tree.focus(email)
            break
    tree.pack(fill='both', expand=True, padx=5, pady=5)
    btn_frame = ttk.Frame(win)
    btn_frame.pack(fill='x', pady=5)

    def refresh_tree():
        for iid in tree.get_children():
            tree.delete(iid)
        for email, info in load_accounts().items():
            display = f"{'★ ' if info.get('default') else ''}{email} ({info.get('name', '')})"
            tree.insert('', 'end', iid=email, values=(display,))

    def proceed():
        sel = tree.selection()
        if not sel:
            return
        result['choice'] = sel[0]
        win.destroy()

    def create():
        result['action'] = 'create'
        win.destroy()

    def set_default():
        sel = tree.selection()
        if not sel:
            return
        accts = load_accounts()
        for v in accts.values():
            v['default'] = False
        accts[sel[0]]['default'] = True
        save_accounts(accts)
        refresh_tree()

    def delete_selected():
        sel = tree.selection()
        if not sel:
            return
        email = sel[0]
        confirm = sd.askstring('Confirm Delete', f'Type the email of the account ({email}) to delete:')
        if confirm != email:
            messagebox.showerror('Error', 'Email confirmation does not match')
            return
        if not messagebox.askyesno('Confirm', f'Delete account {email}? This cannot be undone.'):
            return
        delete_account_data(email)
        refresh_tree()

    ttk.Button(btn_frame, text='Proceed', command=proceed).pack(side='left', padx=5)
    ttk.Button(btn_frame, text='Create New', command=create).pack(side='left', padx=5)
    ttk.Button(btn_frame, text='Set Default', command=set_default).pack(side='left', padx=5)
    ttk.Button(btn_frame, text='Delete', command=delete_selected).pack(side='left', padx=5)
    ttk.Button(btn_frame, text='Cancel', command=win.destroy).pack(side='right', padx=5)
    win.mainloop()
    if result.get('action') == 'create':
        return '__create__'
    return result.get('choice')


def login_flow():
    global ACCOUNT_ID, master_password
    while True:
        accounts = load_accounts()
        if not accounts:
            if create_new_account():
                return True
            continue
        sel = account_selection_gui(accounts)
        if sel is None:
            return False
        if sel == '__create__':
            if create_new_account():
                continue
            else:
                continue
        ACCOUNT_ID = sel
        while True:
            master_password = sd.askstring('Master Password', f'Enter master password for {sel}:', show='*')
            if master_password is None:
                ACCOUNT_ID = None
                break
            if verify_master_password(master_password):
                return True
            messagebox.showerror('Invalid', 'Invalid master password')


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
    return bool(pub.verify(m)), m.message or ''


def generate_keypair(name, email, passphrase):
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = PGPUID.new(name, email=email)
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256],
                compression=[CompressionAlgorithm.ZLIB])
    if passphrase:
        key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return str(key), str(key.pubkey), key.fingerprint


def generate_key_action():
    name = sd.askstring('Name', 'Enter name:')
    if not name:
        return
    email = sd.askstring('Email', 'Enter email:')
    if email is None:
        return
    pp = sd.askstring('Passphrase', 'Set passphrase (optional):', show='*')

    def worker():
        priv_txt, pub_txt, fp = generate_keypair(name, email, pp or None)
        vault = load_keyvault()
        vault[fp] = {'private': priv_txt, 'public': pub_txt}
        save_keyvault(vault)
        messagebox.showinfo('Generated', f'Keypair generated with fingerprint {fp} and stored in vault')

    threading.Thread(target=worker, daemon=True).start()


def open_vault_window():
    win = tk.Toplevel(root)
    win.title('PGP Key Vault')
    treev = ttk.Treeview(win, columns=('fingerprint',), show='headings')
    treev.heading('fingerprint', text='Fingerprint')
    treev.pack(fill='both', expand=True, padx=5, pady=5)

    def refresh():
        treev.delete(*treev.get_children())
        for fp in load_keyvault().keys():
            treev.insert('', 'end', iid=fp, values=(fp,))

    def import_key():
        p = filedialog.askopenfilename(filetypes=[('PGP Key', '*.asc *.pgp'), ('All files', '*.*')])
        if not p:
            return
        with open(p, 'r') as f:
            txt = f.read()
        try:
            k, _ = PGPKey.from_blob(txt)
        except Exception as e:
            messagebox.showerror('Error', str(e))
            return
        fp = k.fingerprint
        vault = load_keyvault()
        entry = vault.get(fp, {})
        if k.is_public:
            entry['public'] = txt
        else:
            entry['private'] = txt
            if 'public' not in entry:
                entry['public'] = str(k.pubkey)
        vault[fp] = entry
        save_keyvault(vault)
        refresh()

    def delete_key():
        sel = treev.selection()
        if not sel:
            return
        fp = sel[0]
        vault = load_keyvault()
        vault.pop(fp, None)
        save_keyvault(vault)
        refresh()

    def export_selected():
        sel = treev.selection()
        if not sel:
            return
        fp = sel[0]
        data = load_keyvault().get(fp, {})
        for typ in ('public', 'private'):
            if typ in data:
                path = filedialog.asksaveasfilename(defaultextension='.asc', filetypes=[('PGP Key', '*.asc')],
                                                    title=f'Save {typ} key')
                if not path:
                    continue
                with open(path, 'w') as f:
                    f.write(data[typ])
                with open(path + '.fingerprint', 'w') as f:
                    f.write(fp)

    btn_frame = ttk.Frame(win)
    btn_frame.pack(fill='x', padx=5, pady=5)
    ttk.Button(btn_frame, text='Import Key', command=import_key).pack(side='left', padx=5, pady=5)
    ttk.Button(btn_frame, text='Delete Key', command=delete_key).pack(side='left', padx=5, pady=5)
    ttk.Button(btn_frame, text='Export Selected', command=export_selected).pack(side='left', padx=5, pady=5)
    refresh()


def encrypt_action():
    key = load_public_key_from_text(public_key_text.get('1.0', tk.END).strip())
    ct = encrypt_message(key, plaintext_text.get('1.0', tk.END))
    ciphertext_text.delete('1.0', tk.END)
    ciphertext_text.insert(tk.END, ct)


def decrypt_action():
    key_text = private_key_text.get('1.0', tk.END).strip()
    ct_blob = ciphertext_input.get('1.0', tk.END).strip()
    pw = passphrase_entry.get()

    def worker(k_txt, ctb, pw_):
        try:
            priv = load_private_key_from_text(k_txt)
            pt = decrypt_message(priv, ctb, pw_)
            root.after(0, lambda: (decrypted_text.delete('1.0', tk.END), decrypted_text.insert(tk.END, pt)))
        except Exception as e:
            root.after(0, lambda: messagebox.showerror('Error', str(e)))

    threading.Thread(target=worker, args=(key_text, ct_blob, pw), daemon=True).start()


def sign_action():
    key = load_private_key_from_text(private_sign_key_text.get('1.0', tk.END).strip())
    msg = sign_input_text.get('1.0', tk.END).rstrip('\n')
    signature = sign_message_detached(key, msg, passphrase_sign_entry.get())
    header = '-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n'
    signed = header + msg + '\n' + str(signature)
    signature_text.delete('1.0', tk.END)
    signature_text.insert(tk.END, signed)


def sign_file_action():
    path = filedialog.askopenfilename(title='Select file to sign')
    if not path:
        return
    with open(path, 'r') as f:
        content = f.read()
    key = load_private_key_from_text(private_sign_key_text.get('1.0', tk.END).strip())
    sig = sign_message_detached(key, content, passphrase_sign_entry.get())
    sig_path = path + '.sig'
    with open(sig_path, 'w') as f:
        f.write(str(sig))
    messagebox.showinfo('Signed', f'Signature saved to {sig_path}')


def verify_action():
    pub = load_public_key_from_text(public_verify_key_text.get('1.0', tk.END).strip())
    sm_blob = verify_input_text.get('1.0', tk.END).strip()
    if not sm_blob:
        messagebox.showerror('Error', 'No signed message')
        return
    try:
        valid, orig = verify_signature(pub, sm_blob)
    except TypeError:
        path = filedialog.askopenfilename(title='Select original message file',
                                          filetypes=[('Text Files', '*.txt'), ('All Files', '*.*')])
        if not path:
            return
        with open(path, 'r') as f:
            orig = f.read()
        sig = PGPMessage.from_blob(sm_blob)
        clear = PGPMessage.new(orig, cleartext=True)
        result = pub.verify(clear, signature=sig)
        valid = all(s.valid for s in result) if hasattr(result, '__iter__') else bool(result)
    verify_output_text.delete('1.0', tk.END)
    verify_output_text.insert(tk.END, f'Valid: {valid}\n\n{orig}')


def load_key_file(kt, w):
    p = filedialog.askopenfilename(filetypes=[('PGP Key Files', '*.asc *.pgp'), ('All files', '*.*')])
    if p:
        with open(p, 'r') as f:
            txt = f.read()
        store_key(kt, txt)
        w.delete('1.0', tk.END)
        w.insert(tk.END, txt)


def copy_to_clipboard(w):
    root.clipboard_clear()
    root.clipboard_append(w.get('1.0', tk.END).strip())


def save_aes_ciphertext_action():
    ct = aes_ciphertext_text.get('1.0', tk.END).strip()
    if not ct:
        messagebox.showerror('Error', 'No ciphertext')
        return
    path = os.path.join(os.path.expanduser('~/Downloads'), 'aes256_ciphertext.txt')
    try:
        with open(path, 'w') as f:
            f.write(ct)
        messagebox.showinfo('Saved', f'Ciphertext saved to {path}')
    except Exception as e:
        messagebox.showerror('Error', str(e))


def export_public_key(kt):
    txt = get_stored_key(kt)
    if not txt:
        messagebox.showerror('Error', 'No key stored')
        return
    try:
        k, _ = PGPKey.from_blob(txt)
        fp = k.fingerprint
    except Exception:
        fp = ''
    path = filedialog.asksaveasfilename(defaultextension='.asc',
                                        filetypes=[('PGP Public Key', '*.asc'), ('All Files', '*.*')])
    if path:
        with open(path, 'w') as f:
            f.write(txt)
        with open(path + '.fingerprint', 'w') as f:
            f.write(fp)
        messagebox.showinfo('Export', f'Public key saved to {path}')


def export_private_key(kt):
    pw = sd.askstring('Password', 'Enter master password:', show='*')
    if not pw or not verify_master_password(pw):
        messagebox.showerror('Error', 'Invalid password')
        return
    txt = get_stored_key(kt)
    if not txt:
        messagebox.showerror('Error', 'No key stored')
        return
    try:
        k, _ = PGPKey.from_blob(txt)
        fp = k.fingerprint
    except Exception:
        fp = ''
    path = filedialog.asksaveasfilename(defaultextension='.asc',
                                        filetypes=[('PGP Private Key', '*.asc'), ('All Files', '*.*')])
    if path:
        with open(path, 'w') as f:
            f.write(txt)
        with open(path + '.fingerprint', 'w') as f:
            f.write(fp)
        messagebox.showinfo('Export', f'Private key saved to {path}')


def save_encrypted_action():
    ct = ciphertext_text.get('1.0', tk.END).strip()
    if not ct:
        messagebox.showerror('Error', 'No ciphertext')
        return
    path = filedialog.asksaveasfilename(defaultextension='.pgp',
                                        filetypes=[('PGP Files', '*.pgp'), ('All Files', '*.*')])
    if path:
        with open(path, 'w') as f:
            f.write(ct)
        messagebox.showinfo('Saved', f'Encrypted message saved to {path}')


def save_decrypted_action():
    pt = decrypted_text.get('1.0', tk.END)
    if not pt.strip():
        messagebox.showerror('Error', 'No decrypted text')
        return
    path = filedialog.asksaveasfilename(defaultextension='.txt',
                                        filetypes=[('Text Files', '*.txt'), ('All Files', '*.*')])
    if path:
        with open(path, 'w') as f:
            f.write(pt)
        messagebox.showinfo('Saved', f'Decrypted message saved to {path}')


def set_unique_aes():
    global aes_secret_key
    key = sd.askstring('AES Key', 'Enter unique AES key\n(leave blank to use master password):', show='*')
    if key:
        aes_secret_key = key
        aes_mode_label.config(text='AES mode: Unique Key')
    else:
        aes_secret_key = None
        aes_mode_label.config(text='AES mode: Master Password')


def use_master_aes():
    global aes_secret_key
    aes_secret_key = None
    aes_mode_label.config(text='AES mode: Master Password')


def aes_encrypt_action():
    pw = aes_secret_key if aes_secret_key else master_password
    ct = aes_encrypt(pw, aes_plaintext_text.get('1.0', tk.END))
    aes_ciphertext_text.delete('1.0', tk.END)
    aes_ciphertext_text.insert(tk.END, ct)


def aes_decrypt_action():
    pw = aes_secret_key if aes_secret_key else master_password
    token = aes_ciphertext_text.get('1.0', tk.END).strip()
    try:
        pt = aes_decrypt(pw, token)
        aes_decrypted_text.delete('1.0', tk.END)
        aes_decrypted_text.insert(tk.END, pt)
    except Exception as e:
        messagebox.showerror('Error', str(e))


def aes_encrypt_file_action():
    pw = aes_secret_key if aes_secret_key else master_password
    path = filedialog.askopenfilename(title='Select file to encrypt')
    if not path:
        return
    with open(path, 'rb') as f:
        data = f.read()
    key = derive_aes_key(pw)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    out_path = path + '.aes256'
    with open(out_path, 'wb') as f:
        f.write(iv + ct)
    messagebox.showinfo('Encrypted', f'File encrypted to {out_path}')


def aes_decrypt_file_action():
    pw = aes_secret_key if aes_secret_key else master_password
    path = filedialog.askopenfilename(title='Select encrypted file to decrypt',
                                      filetypes=[('Encrypted Files', '*.aes256 *.enc'), ('All Files', '*.*')])
    if not path:
        return
    try:
        with open(path, 'rb') as f:
            raw = f.read()
        iv, ct = raw[:16], raw[16:]
        key = derive_aes_key(pw)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded) + unpadder.finalize()
    except Exception as e:
        messagebox.showerror('Error', str(e))
        return
    base, ext = os.path.splitext(path)
    out_path = base if ext.lower() in ('.aes256', '.enc') else path + '.dec'
    try:
        with open(out_path, 'wb') as f:
            f.write(data)
        messagebox.showinfo('Decrypted', f'File decrypted to {out_path}')
    except Exception as e:
        messagebox.showerror('Error', str(e))


def add_cred():
    site = sd.askstring('Site', 'Enter site:')
    if not site:
        return
    username = sd.askstring('Username', 'Enter username:')
    if username is None:
        return
    password = sd.askstring('Password', 'Enter password:', show='*')
    if password is None:
        return
    creds = load_credentials()
    creds[site] = {'username': username, 'password': password}
    save_credentials(creds)
    refresh_credentials_view()


def edit_cred():
    sel = tree.selection()
    if not sel:
        return
    site = sel[0]
    creds = load_credentials()
    info = creds.get(site, {})
    new_user = sd.askstring('Username', 'Edit username:', initialvalue=info.get('username', ''))
    if new_user is None:
        return
    new_pass = sd.askstring('Password', 'Edit password:', show='*', initialvalue=info.get('password', ''))
    if new_pass is None:
        return
    creds[site] = {'username': new_user, 'password': new_pass}
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
    pwd = creds.get(site, {}).get('password', '')
    messagebox.showinfo('Password', f'{site}: {pwd}')


def copy_selected(field):
    sel = tree.selection()
    if not sel:
        return
    site = sel[0]
    creds = load_credentials()
    val = creds.get(site, {}).get(field, '')
    root.clipboard_clear()
    root.clipboard_append(val)


if not login_flow():
    exit()

root = tk.Tk()
root.title(f'PDFSage PGP & AES & PW Vault Tool - {ACCOUNT_ID}')
menubar = tk.Menu(root)
acct_menu = tk.Menu(menubar, tearoff=0)
acct_menu.add_command(label='Change Master Password', command=change_master_password)
acct_menu.add_command(label='Delete Account', command=delete_account)
menubar.add_cascade(label='Account', menu=acct_menu)
keys_menu = tk.Menu(menubar, tearoff=0)
keys_menu.add_command(label='Save Encryption Public Key',
                      command=lambda: store_key('public_key', public_key_text.get('1.0', tk.END).strip()) or
                                      messagebox.showinfo('Saved', 'Public key stored'))
keys_menu.add_command(label='Save Encryption Private Key',
                      command=lambda: store_key('private_key', private_key_text.get('1.0', tk.END).strip()) or
                                      messagebox.showinfo('Saved', 'Private key stored'))
keys_menu.add_command(label='Save Signing Private Key',
                      command=lambda: store_key('sign_private_key', private_sign_key_text.get('1.0', tk.END).strip()) or
                                      messagebox.showinfo('Saved', 'Signing key stored'))
keys_menu.add_command(label='Save Verify Public Key',
                      command=lambda: store_key('verify_public_key', public_verify_key_text.get('1.0', tk.END).strip()) or
                                      messagebox.showinfo('Saved', 'Verify public key stored'))
keys_menu.add_separator()
keys_menu.add_command(label='Generate Keypair', command=generate_key_action)
keys_menu.add_command(label='Open Key Vault', command=open_vault_window)
menubar.add_cascade(label='Keys', menu=keys_menu)
root.config(menu=menubar)
nb = ttk.Notebook(root)
encrypt_frame = ttk.Frame(nb)
decrypt_frame = ttk.Frame(nb)
sign_frame = ttk.Frame(nb)
verify_frame = ttk.Frame(nb)
aes_frame = ttk.Frame(nb)
nb.add(encrypt_frame, text='Encrypt')
nb.add(decrypt_frame, text='Decrypt')
nb.add(sign_frame, text='Sign')
nb.add(verify_frame, text='Verify')
nb.add(aes_frame, text='AES256')
nb.pack(expand=1, fill='both')
pub_frame = ttk.LabelFrame(encrypt_frame, text='Public Key')
pub_frame.pack(fill='x', padx=5, pady=5)
public_key_text = scrolledtext.ScrolledText(pub_frame, height=10)
public_key_text.pack(fill='x', padx=5, pady=5)
stored = get_stored_key('public_key')
if stored:
    public_key_text.insert('1.0', stored)
ttk.Button(pub_frame, text='Load Public Key',
           command=lambda: load_key_file('public_key', public_key_text)).pack(padx=5, pady=5)
ttk.Button(pub_frame, text='Export Public Key',
           command=lambda: export_public_key('public_key')).pack(padx=5, pady=5)
pt_frame = ttk.LabelFrame(encrypt_frame, text='Plaintext')
pt_frame.pack(fill='both', expand=True, padx=5, pady=5)
plaintext_text = scrolledtext.ScrolledText(pt_frame, height=10)
plaintext_text.pack(fill='both', expand=True, padx=5, pady=5)
ttk.Button(encrypt_frame, text='Encrypt', command=encrypt_action).pack(padx=5, pady=5)
ct_frame = ttk.LabelFrame(encrypt_frame, text='Ciphertext')
ct_frame.pack(fill='both', expand=True, padx=5, pady=5)
ciphertext_text = scrolledtext.ScrolledText(ct_frame, height=10)
ciphertext_text.pack(fill='both', expand=True, padx=5, pady=5)
ttk.Button(encrypt_frame, text='Copy Encrypted',
           command=lambda: copy_to_clipboard(ciphertext_text)).pack(padx=5, pady=5)
ttk.Button(encrypt_frame, text='Save Encrypted', command=save_encrypted_action).pack(padx=5, pady=5)
priv_frame = ttk.LabelFrame(decrypt_frame, text='Private Key')
priv_frame.pack(fill='x', padx=5, pady=5)
private_key_text = scrolledtext.ScrolledText(priv_frame, height=10)
private_key_text.pack(fill='x', padx=5, pady=5)
stored_priv = get_stored_key('private_key')
if stored_priv:
    private_key_text.insert('1.0', stored_priv)
ttk.Button(priv_frame, text='Load Private Key',
           command=lambda: load_key_file('private_key', private_key_text)).pack(padx=5, pady=5)
ttk.Button(priv_frame, text='Export Private Key',
           command=lambda: export_private_key('private_key')).pack(padx=5, pady=5)
pp_frame = ttk.LabelFrame(decrypt_frame, text='Passphrase')
pp_frame.pack(fill='x', padx=5, pady=5)
passphrase_entry = ttk.Entry(pp_frame, show='*')
passphrase_entry.pack(fill='x', padx=5, pady=5)
dec_in_frame = ttk.LabelFrame(decrypt_frame, text='Ciphertext')
dec_in_frame.pack(fill='both', expand=True, padx=5, pady=5)
ciphertext_input = scrolledtext.ScrolledText(dec_in_frame, height=10)
ciphertext_input.pack(fill='both', expand=True, padx=5, pady=5)
ttk.Button(decrypt_frame, text='Decrypt', command=decrypt_action).pack(padx=5, pady=5)
dec_out_frame = ttk.LabelFrame(decrypt_frame, text='Plaintext')
dec_out_frame.pack(fill='both', expand=True, padx=5, pady=5)
decrypted_text = scrolledtext.ScrolledText(dec_out_frame, height=10)
decrypted_text.pack(fill='both', expand=True, padx=5, pady=5)
ttk.Button(decrypt_frame, text='Copy Decrypted',
           command=lambda: copy_to_clipboard(decrypted_text)).pack(padx=5, pady=5)
ttk.Button(decrypt_frame, text='Save Decrypted', command=save_decrypted_action).pack(padx=5, pady=5)
spriv_frame = ttk.LabelFrame(sign_frame, text='Private Key')
spriv_frame.pack(fill='x', padx=5, pady=5)
private_sign_key_text = scrolledtext.ScrolledText(spriv_frame, height=10)
private_sign_key_text.pack(fill='x', padx=5, pady=5)
stored_sign = get_stored_key('sign_private_key')
if stored_sign:
    private_sign_key_text.insert('1.0', stored_sign)
ttk.Button(spriv_frame, text='Load Private Key',
           command=lambda: load_key_file('sign_private_key', private_sign_key_text)).pack(padx=5, pady=5)
ttk.Button(spriv_frame, text='Export Private Key',
           command=lambda: export_private_key('sign_private_key')).pack(padx=5, pady=5)
spp_frame = ttk.LabelFrame(sign_frame, text='Passphrase')
spp_frame.pack(fill='x', padx=5, pady=5)
passphrase_sign_entry = ttk.Entry(spp_frame, show='*')
passphrase_sign_entry.pack(fill='x', padx=5, pady=5)
sin_frame = ttk.LabelFrame(sign_frame, text='Message')
sin_frame.pack(fill='both', expand=True, padx=5, pady=5)
sign_input_text = scrolledtext.ScrolledText(sin_frame, height=10)
sign_input_text.pack(fill='both', expand=True, padx=5, pady=5)
ttk.Button(sign_frame, text='Sign', command=sign_action).pack(side='left', padx=5, pady=5)
ttk.Button(sign_frame, text='Sign File', command=sign_file_action).pack(side='left', padx=5, pady=5)
sout_frame = ttk.LabelFrame(sign_frame, text='Signed Message')
sout_frame.pack(fill='both', expand=True, padx=5, pady=5)
signature_text = scrolledtext.ScrolledText(sout_frame, height=10)
signature_text.pack(fill='both', expand=True, padx=5, pady=5)
ttk.Button(sign_frame, text='Copy Signature',
           command=lambda: copy_to_clipboard(signature_text)).pack(padx=5, pady=5)
vpub_frame = ttk.LabelFrame(verify_frame, text='Public Key')
vpub_frame.pack(fill='x', padx=5, pady=5)
public_verify_key_text = scrolledtext.ScrolledText(vpub_frame, height=10)
public_verify_key_text.pack(fill='x', padx=5, pady=5)
stored_ver = get_stored_key('verify_public_key')
if stored_ver:
    public_verify_key_text.insert('1.0', stored_ver)
ttk.Button(vpub_frame, text='Load Public Key',
           command=lambda: load_key_file('verify_public_key', public_verify_key_text)).pack(padx=5, pady=5)
ttk.Button(vpub_frame, text='Export Public Key',
           command=lambda: export_public_key('verify_public_key')).pack(padx=5, pady=5)
vin_frame = ttk.LabelFrame(verify_frame, text='Signed Message')
vin_frame.pack(fill='both', expand=True, padx=5, pady=5)
verify_input_text = scrolledtext.ScrolledText(vin_frame, height=10)
verify_input_text.pack(fill='both', expand=True, padx=5, pady=5)
ttk.Button(verify_frame, text='Verify', command=verify_action).pack(padx=5, pady=5)
vout_frame = ttk.LabelFrame(verify_frame, text='Original Message')
vout_frame.pack(fill='both', expand=True, padx=5, pady=5)
verify_output_text = scrolledtext.ScrolledText(vout_frame, height=10)
verify_output_text.pack(fill='both', expand=True, padx=5, pady=5)
pas_frame = ttk.LabelFrame(aes_frame, text='AES Mode')
pas_frame.pack(fill='x', padx=5, pady=5)
aes_mode_label = ttk.Label(pas_frame, text='AES mode: Master Password')
aes_mode_label.pack(side='left', padx=5, pady=5)
ttk.Button(pas_frame, text='Set AES Key', command=set_unique_aes).pack(side='left', padx=5, pady=5)
ttk.Button(pas_frame, text='Use Master Password', command=use_master_aes).pack(side='left', padx=5, pady=5)
plain_frame = ttk.LabelFrame(aes_frame, text='Plaintext')
plain_frame.pack(fill='both', expand=True, padx=5, pady=5)
aes_plaintext_text = scrolledtext.ScrolledText(plain_frame, height=10)
aes_plaintext_text.pack(fill='both', expand=True, padx=5, pady=5)
ttk.Button(aes_frame, text='Encrypt', command=aes_encrypt_action).pack(side='left', padx=5, pady=5)
cipher_frame = ttk.LabelFrame(aes_frame, text='Ciphertext')
cipher_frame.pack(fill='both', expand=True, padx=5, pady=5)
aes_ciphertext_text = scrolledtext.ScrolledText(cipher_frame, height=10)
aes_ciphertext_text.pack(fill='both', expand=True, padx=5, pady=5)
ttk.Button(aes_frame, text='Decrypt', command=aes_decrypt_action).pack(side='left', padx=5, pady=5)
ttk.Button(aes_frame, text='Encrypt File', command=aes_encrypt_file_action).pack(side='left', padx=5, pady=5)
ttk.Button(aes_frame, text='Decrypt File', command=aes_decrypt_file_action).pack(side='left', padx=5, pady=5)
ttk.Button(aes_frame, text='Copy Ciphertext',
           command=lambda: copy_to_clipboard(aes_ciphertext_text)).pack(side='left', padx=5, pady=5)
ttk.Button(aes_frame, text='Save Ciphertext', command=save_aes_ciphertext_action).pack(side='left', padx=5, pady=5)
dec_frame = ttk.LabelFrame(aes_frame, text='Decrypted')
dec_frame.pack(fill='both', expand=True, padx=5, pady=5)
aes_decrypted_text = scrolledtext.ScrolledText(dec_frame, height=10)
aes_decrypted_text.pack(fill='both', expand=True, padx=5, pady=5)
cred_frame = ttk.Frame(nb)
nb.add(cred_frame, text='Credentials')
columns = ('site', 'username', 'password')
tree = ttk.Treeview(cred_frame, columns=columns, show='headings')
for col in columns:
    tree.heading(col, text=col.capitalize())
tree.pack(fill='both', expand=True, padx=5, pady=5)
button_frame = ttk.Frame(cred_frame)
button_frame.pack(fill='x', padx=5, pady=5)
ttk.Button(button_frame, text='Add', command=add_cred).pack(side='left')
ttk.Button(button_frame, text='Edit', command=edit_cred).pack(side='left')
ttk.Button(button_frame, text='Delete', command=delete_cred).pack(side='left')
ttk.Button(button_frame, text='Show', command=show_password).pack(side='left')
ttk.Button(button_frame, text='Copy Password', command=lambda: copy_selected('password')).pack(side='left')
ttk.Button(button_frame, text='Copy Username', command=lambda: copy_selected('username')).pack(side='left')


def refresh_credentials_view():
    for i in tree.get_children():
        tree.delete(i)
    for site, info in load_credentials().items():
        tree.insert('', 'end', iid=site, values=(site, info['username'], '******'))


refresh_credentials_view()
hash_frame = ttk.Frame(nb)
nb.add(hash_frame, text='Check Hash')
source_var = tk.StringVar(value='text')
ttk.Radiobutton(hash_frame, text='Text', variable=source_var, value='text').pack(anchor='w', padx=5, pady=5)
ttk.Radiobutton(hash_frame, text='File', variable=source_var, value='file').pack(anchor='w', padx=5, pady=5)
text_frame_hash = ttk.LabelFrame(hash_frame, text='Text Input')
text_frame_hash.pack(fill='both', expand=True, padx=5, pady=5)
hash_text_input = scrolledtext.ScrolledText(text_frame_hash, height=5)
hash_text_input.pack(fill='both', expand=True, padx=5, pady=5)
file_frame_hash = ttk.Frame(hash_frame)
file_frame_hash.pack(fill='x', padx=5, pady=5)
file_path_var = tk.StringVar()
ttk.Entry(file_frame_hash, textvariable=file_path_var).pack(side='left', fill='x', expand=True, padx=5, pady=5)


def browse_file_hash():
    p = filedialog.askopenfilename()
    if p:
        file_path_var.set(p)
        source_var.set('file')


ttk.Button(file_frame_hash, text='Browse', command=browse_file_hash).pack(side='left', padx=5, pady=5)
md5_var = tk.StringVar()
sha256_var = tk.StringVar()


def compute_hashes():
    if source_var.get() == 'text':
        data = hash_text_input.get('1.0', tk.END).encode()
    else:
        fp = file_path_var.get()
        if not fp:
            messagebox.showerror('Error', 'No file selected')
            return
        try:
            with open(fp, 'rb') as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror('Error', str(e))
            return
    md5_var.set(hashlib.md5(data).hexdigest())
    sha256_var.set(hashlib.sha256(data).hexdigest())


def verify_hash():
    h = verify_entry_hash.get().strip().lower()
    if not h:
        messagebox.showerror('Error', 'No hash to verify')
        return
    computed = md5_var.get().lower() if verify_alg_var.get() == 'MD5' else sha256_var.get().lower()
    if h == computed:
        messagebox.showinfo('Result', 'CONGRATS these hash match!')
    else:
        messagebox.showwarning('Result', 'WARNING no hash verification')


ttk.Button(hash_frame, text='Compute Hashes', command=compute_hashes).pack(padx=5, pady=5)
ttk.Label(hash_frame, text='MD5:').pack(anchor='w', padx=5, pady=2)
ttk.Entry(hash_frame, textvariable=md5_var, state='readonly').pack(fill='x', padx=5, pady=2)
ttk.Label(hash_frame, text='SHA256:').pack(anchor='w', padx=5, pady=2)
ttk.Entry(hash_frame, textvariable=sha256_var, state='readonly').pack(fill='x', padx=5, pady=2)
verify_frame_hash = ttk.Frame(hash_frame)
verify_frame_hash.pack(fill='x', padx=5, pady=5)
verify_entry_hash = ttk.Entry(verify_frame_hash)
verify_entry_hash.pack(side='left', fill='x', expand=True, padx=5, pady=5)
verify_alg_var = tk.StringVar(value='MD5')
ttk.OptionMenu(verify_frame_hash, verify_alg_var, 'MD5', 'MD5', 'SHA256').pack(side='left', padx=5, pady=5)
ttk.Button(hash_frame, text='Verify Hash', command=verify_hash).pack(padx=5, pady=5)


def on_close():
    global master_password, fernet, aes_secret_key
    master_password = None
    fernet = None
    aes_secret_key = None
    root.destroy()


root.protocol('WM_DELETE_WINDOW', on_close)
try:
    root.mainloop()
finally:
    master_password = None
    fernet = None
    aes_secret_key = None