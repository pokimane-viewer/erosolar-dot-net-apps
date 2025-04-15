from flask import Flask, request, render_template_string, Response, send_file
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
import os
import uuid
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from io import BytesIO
from werkzeug.utils import secure_filename

app = Flask(__name__)
keys_store = {}
aes_store = {}

html_template = '''<html>
<head><title>PGP Key Generation</title></head>
<body>
<h2>Generate RSA4096 PGP Key Pair</h2>
<form method="post">
Name: <input type="text" name="name" required><br>
Email: <input type="email" name="email" required><br>
Comment: <input type="text" name="comment"><br>
Passphrase: <input type="password" name="passphrase"><br>
<input type="submit" value="Generate Key Pair">
</form>
{% if public_key %}
<h3>Public Key</h3>
<pre>{{ public_key }}</pre>
<a href="/download_private?name={{ filename }}">Download Private Key</a><br>
<a href="/download_public?name={{ filename }}">Download Public Key</a>
{% endif %}
<hr>
<a href="/aes_encrypt">AES256 Encrypt</a> | <a href="/aes_decrypt">AES256 Decrypt</a>
</body>
</html>'''

html_aes_encrypt = '''<html>
<head><title>AES256 Encrypt</title></head>
<body>
<h2>AES256 Encrypt</h2>
<form method="post" enctype="multipart/form-data">
Select file: <input type="file" name="file" required><br>
Password: <input type="password" name="password" required><br>
<input type="submit" value="Encrypt">
</form>
{% if encrypted %}
<h3>Encrypted File</h3>
<a href="/download_encrypted?fname={{ filename }}">Download Encrypted File</a>
{% endif %}
<hr>
<a href="/">Back</a>
</body>
</html>'''

html_aes_decrypt = '''<html>
<head><title>AES256 Decrypt</title></head>
<body>
<h2>AES256 Decrypt</h2>
<form method="post" enctype="multipart/form-data">
Select encrypted file: <input type="file" name="file" required><br>
Password: <input type="password" name="password" required><br>
<input type="submit" value="Decrypt">
</form>
{% if error %}<p style="color:red;">{{ error }}</p>{% endif %}
<hr>
<a href="/">Back</a>
</body>
</html>'''

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        comment = request.form.get('comment', '')
        passphrase = request.form.get('passphrase', None)
        uid = pgpy.PGPUID.new(name, comment=comment, email=email)
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    hashes=[HashAlgorithm.SHA256],
                    ciphers=[SymmetricKeyAlgorithm.AES256],
                    compression=[CompressionAlgorithm.Uncompressed])
        if passphrase:
            key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
        public_key_str = str(key.pubkey)
        private_key_str = str(key)
        filename = name.replace(" ", "_")
        keys_store[filename] = {'public': public_key_str, 'private': private_key_str}
        return render_template_string(html_template, public_key=public_key_str, filename=filename)
    return render_template_string(html_template)

@app.route('/download_public')
def download_public():
    filename = request.args.get('name')
    if filename in keys_store:
        return Response(keys_store[filename]['public'], mimetype='application/pgp-keys',
                        headers={"Content-Disposition": f"attachment;filename={filename}_public.asc"})
    return "Key not found", 404

@app.route('/download_private')
def download_private():
    filename = request.args.get('name')
    if filename in keys_store:
        return Response(keys_store[filename]['private'], mimetype='application/pgp-keys',
                        headers={"Content-Disposition": f"attachment;filename={filename}_private.asc"})
    return "Key not found", 404

@app.route('/aes_encrypt', methods=['GET', 'POST'])
def aes_encrypt():
    if request.method == 'POST':
        file = request.files['file']
        password = request.form['password']
        data = file.read()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
        key = kdf.derive(password.encode())
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        encrypted_blob = salt + iv + encrypted_data
        fname = uuid.uuid4().hex + "_" + secure_filename(file.filename)
        aes_store[fname] = encrypted_blob
        return render_template_string(html_aes_encrypt, encrypted=True, filename=fname)
    return render_template_string(html_aes_encrypt)

@app.route('/download_encrypted')
def download_encrypted():
    fname = request.args.get('fname')
    if fname in aes_store:
        return Response(aes_store[fname], mimetype='application/octet-stream',
                        headers={"Content-Disposition": f"attachment;filename={fname}.enc"})
    return "Encrypted file not found", 404

@app.route('/aes_decrypt', methods=['GET', 'POST'])
def aes_decrypt():
    if request.method == 'POST':
        file = request.files['file']
        password = request.form['password']
        try:
            content = file.read()
            salt, iv, enc_data = content[:16], content[16:32], content[32:]
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
            key = kdf.derive(password.encode())
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            dec_data = decryptor.update(enc_data) + decryptor.finalize()
            return send_file(BytesIO(dec_data), as_attachment=True, download_name="decrypted_file", mimetype="application/octet-stream")
        except Exception:
            return render_template_string(html_aes_decrypt, error="Decryption failed")
    return render_template_string(html_aes_decrypt)

if __name__ == '__main__':
    app.run()