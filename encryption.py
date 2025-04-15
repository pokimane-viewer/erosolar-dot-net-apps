from flask import Flask, request, render_template, Response, send_file
import pgpy, os, uuid
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from io import BytesIO
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jinja2 import DictLoader

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
keys_store = {}
aes_store = {}
pgp_store = {}
raw_rsa_store = {}

@app.context_processor
def inject_base_path():
    return dict(base_path="/encryption")

base_template = '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title if title else "Encryption App" }}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ base_path }}/">Encryption App</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav">
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/">PGP/AES/RSA Home</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/aes_encrypt">AES Encrypt</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/aes_decrypt">AES Decrypt</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/pgp_encrypt">PGP Encrypt</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/pgp_demo">PGP Demo</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/raw_rsa">Raw RSA</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/rsa_hand">RSA Demo</a></li>
      </ul>
    </div>
  </div>
</nav>
<div class="container">
  {% block content %}{% endblock %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

index_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>Generate RSA4096 PGP Key Pair</h2></div>
  <div class="card-body">
    <form method="post">
      <div class="mb-3"><label class="form-label">Name:</label><input type="text" name="name" class="form-control" required></div>
      <div class="mb-3"><label class="form-label">Email:</label><input type="email" name="email" class="form-control" required></div>
      <div class="mb-3"><label class="form-label">Comment:</label><input type="text" name="comment" class="form-control"></div>
      <div class="mb-3"><label class="form-label">Passphrase:</label><input type="password" name="passphrase" class="form-control"></div>
      <button type="submit" class="btn btn-primary">Generate Key Pair</button>
    </form>
    <p class="mt-3">Note: Unlike AES256 encryption keys which are unique per file and processed temporarily in RAM, your generated PGP secret key is permanently attached to your identity. To change it, generate a new key pair.</p>
    {% if public_key %}
    <hr>
    <h3>Public Key</h3>
    <pre class="bg-light p-3">{{ public_key }}</pre>
    <a href="{{ base_path }}/download_private?name={{ filename }}" class="btn btn-secondary">Download Private Key</a>
    <a href="{{ base_path }}/download_public?name={{ filename }}" class="btn btn-secondary">Download Public Key</a>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

aes_encrypt_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>AES256 Encrypt</h2></div>
  <div class="card-body">
    <form method="post" enctype="multipart/form-data">
      <div class="mb-3"><label class="form-label">Select file:</label><input type="file" name="file" class="form-control" required></div>
      <div class="mb-3"><label class="form-label">Password:</label><input type="password" name="password" class="form-control" required></div>
      <button type="submit" class="btn btn-primary">Encrypt</button>
    </form>
    <p class="mt-3">Note: Your AES secret key is securely stored and unlocked by your password. The key is processed only temporarily in RAM on the server.</p>
    {% if encrypted %}
    <hr>
    <h3>Encrypted File</h3>
    <a href="{{ base_path }}/download_encrypted?fname={{ filename }}" class="btn btn-secondary">Download Encrypted File</a>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

aes_decrypt_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>AES256 Decrypt</h2></div>
  <div class="card-body">
    <form method="post" enctype="multipart/form-data">
      <div class="mb-3"><label class="form-label">Select encrypted file:</label><input type="file" name="file" class="form-control" required></div>
      <div class="mb-3"><label class="form-label">Password:</label><input type="password" name="password" class="form-control" required></div>
      <button type="submit" class="btn btn-primary">Decrypt</button>
    </form>
    <p class="mt-3">Note: Your AES secret key is securely stored and unlocked by your password. The key is processed only temporarily in RAM on the server.</p>
    {% if error %}<p class="text-danger">{{ error }}</p>{% endif %}
  </div>
</div>
{% endblock %}
'''

pgp_encrypt_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>PGP Encrypt Message</h2></div>
  <div class="card-body">
    <form method="post">
      <div class="mb-3"><label class="form-label">Recipient Public Key:</label><textarea name="recipient_key" rows="10" class="form-control" required></textarea></div>
      <div class="mb-3"><label class="form-label">Message:</label><textarea name="message" rows="5" class="form-control" required></textarea></div>
      <button type="submit" class="btn btn-primary">Encrypt</button>
    </form>
    {% if encrypted_message %}
    <hr>
    <h3>Encrypted Message</h3>
    <pre class="bg-light p-3">{{ encrypted_message }}</pre>
    <a href="{{ base_path }}/download_pgp?fname={{ filename }}" class="btn btn-secondary">Download Encrypted Message</a>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

pgp_demo_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>PGP Demo</h2></div>
  <div class="card-body">
    <p>Note: Your generated PGP secret key is permanently attached to your identity. To change it, generate a new key pair.</p>
    <form method="post">
      <div class="mb-3"><label class="form-label">Message to Encrypt:</label><textarea name="demo_message" rows="5" class="form-control" required></textarea></div>
      <button type="submit" class="btn btn-primary">Generate Keys and Encrypt/Decrypt</button>
    </form>
    {% if public_key %}
    <hr>
    <h3>Generated Public Key</h3>
    <pre class="bg-light p-3">{{ public_key }}</pre>
    <h3>Generated Private Key</h3>
    <pre class="bg-light p-3">{{ private_key }}</pre>
    <h3>Original Message</h3>
    <pre class="bg-light p-3">{{ original_message }}</pre>
    <h3>Encrypted Message</h3>
    <pre class="bg-light p-3">{{ encrypted_message }}</pre>
    <h3>Decrypted Message</h3>
    <pre class="bg-light p-3">{{ decrypted_message }}</pre>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

raw_rsa_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>Raw RSA Key Pair Generation</h2></div>
  <div class="card-body">
    <form method="post">
      <button type="submit" class="btn btn-primary">Generate RSA Key Pair</button>
    </form>
    {% if private_key %}
    <hr>
    <h3>Private Key (PEM Format)</h3>
    <pre class="bg-light p-3">{{ private_key }}</pre>
    <a href="{{ base_path }}/download_raw_private?rid={{ rid }}" class="btn btn-secondary">Download Private Key</a>
    <h3>Public Key (OpenSSH Format)</h3>
    <pre class="bg-light p-3">{{ public_key }}</pre>
    <a href="{{ base_path }}/download_raw_public?rid={{ rid }}" class="btn btn-secondary">Download Public Key</a>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

rsa_hand_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>Interactive RSA Demo</h2></div>
  <div class="card-body">
    <form method="post">
      <div class="mb-3"><label class="form-label">Enter prime p (less than 100):</label><input type="number" name="p" class="form-control" required></div>
      <div class="mb-3"><label class="form-label">Enter prime q (less than 100):</label><input type="number" name="q" class="form-control" required></div>
      <div class="mb-3"><label class="form-label">Enter a short message (max 100 characters):</label><input type="text" name="message" maxlength="100" class="form-control" required></div>
      <button type="submit" class="btn btn-primary">Run RSA Demo</button>
    </form>
    {% if error %}
    <p class="text-danger mt-3">{{ error }}</p>
    {% endif %}
    {% if p %}
    <hr>
    <h3>RSA Parameters:</h3>
    <p>p: {{ p }}, q: {{ q }}</p>
    <p>n = p * q: {{ n }}</p>
    <p>&Phi;(n): {{ phi }}</p>
    <p>Public exponent (e): {{ e }}</p>
    <p>Private exponent (d): {{ d }}</p>
    <h3>Encryption Process:</h3>
    <p>Original Message: "{{ message }}"</p>
    <p>Message as numbers (ASCII codes): {{ orig_numbers }}</p>
    <p>Encrypted numbers: {{ encrypted_numbers }}</p>
    <h3>Decryption Process:</h3>
    <p>Decrypted numbers: {{ decrypted_numbers }}</p>
    <p>Decrypted Message: "{{ decrypted_message }}"</p>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

template_dict = {
    'base.html': base_template,
    'index.html': index_template,
    'aes_encrypt.html': aes_encrypt_template,
    'aes_decrypt.html': aes_decrypt_template,
    'pgp_encrypt.html': pgp_encrypt_template,
    'pgp_demo.html': pgp_demo_template,
    'raw_rsa.html': raw_rsa_template,
    'rsa_hand.html': rsa_hand_template,
}

app.jinja_loader = DictLoader(template_dict)

@app.route('/encryption/', methods=['GET', 'POST'])
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
        return render_template('index.html', public_key=public_key_str, filename=filename)
    return render_template('index.html')

@app.route('/encryption/download_public')
def download_public():
    filename = request.args.get('name')
    if filename in keys_store:
        return Response(keys_store[filename]['public'], mimetype='application/pgp-keys',
                        headers={"Content-Disposition": f"attachment;filename={filename}_public.asc"})
    return "Key not found", 404

@app.route('/encryption/download_private')
def download_private():
    filename = request.args.get('name')
    if filename in keys_store:
        return Response(keys_store[filename]['private'], mimetype='application/pgp-keys',
                        headers={"Content-Disposition": f"attachment;filename={filename}_private.asc"})
    return "Key not found", 404

@app.route('/encryption/aes_encrypt', methods=['GET', 'POST'])
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
        return render_template('aes_encrypt.html', encrypted=True, filename=fname)
    return render_template('aes_encrypt.html')

@app.route('/encryption/download_encrypted')
def download_encrypted():
    fname = request.args.get('fname')
    if fname in aes_store:
        return Response(aes_store[fname], mimetype='application/octet-stream',
                        headers={"Content-Disposition": f"attachment;filename={fname}.enc"})
    return "Encrypted file not found", 404

@app.route('/encryption/aes_decrypt', methods=['GET', 'POST'])
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
            return render_template('aes_decrypt.html', error="Decryption failed")
    return render_template('aes_decrypt.html')

@app.route('/encryption/pgp_encrypt', methods=['GET', 'POST'])
def pgp_encrypt():
    if request.method == 'POST':
        recipient_key_blob = request.form['recipient_key']
        message_text = request.form['message']
        try:
            recipient_pub_key, _ = pgpy.PGPKey.from_blob(recipient_key_blob)
            msg = pgpy.PGPMessage.new(message_text)
            encrypted = recipient_pub_key.encrypt(msg)
            encrypted_message_str = str(encrypted)
            fname = uuid.uuid4().hex
            pgp_store[fname] = encrypted_message_str
            return render_template('pgp_encrypt.html', encrypted_message=encrypted_message_str, filename=fname)
        except Exception as e:
            return render_template('pgp_encrypt.html', encrypted_message="Encryption Error: " + str(e))
    return render_template('pgp_encrypt.html')

@app.route('/encryption/download_pgp')
def download_pgp():
    fname = request.args.get('fname')
    if fname in pgp_store:
        return Response(pgp_store[fname], mimetype='application/pgp-keys',
                        headers={"Content-Disposition": f"attachment;filename={fname}_encrypted.asc"})
    return "Encrypted message not found", 404

@app.route('/encryption/pgp_demo', methods=['GET', 'POST'])
def pgp_demo():
    if request.method == 'POST':
        demo_message = request.form['demo_message']
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
        uid = pgpy.PGPUID.new("Demo User", email="demo@example.com")
        key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    hashes=[HashAlgorithm.SHA256],
                    ciphers=[SymmetricKeyAlgorithm.AES256],
                    compression=[CompressionAlgorithm.Uncompressed])
        public_key_str = str(key.pubkey)
        private_key_str = str(key)
        msg = pgpy.PGPMessage.new(demo_message)
        encrypted_msg = key.pubkey.encrypt(msg)
        decrypted_msg = key.decrypt(encrypted_msg).message
        return render_template('pgp_demo.html', public_key=public_key_str, private_key=private_key_str,
                               original_message=demo_message, encrypted_message=str(encrypted_msg), decrypted_message=decrypted_msg)
    return render_template('pgp_demo.html')

@app.route('/encryption/raw_rsa', methods=['GET', 'POST'])
def raw_rsa():
    if request.method == 'POST':
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = private_key.public_key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        rid = uuid.uuid4().hex
        raw_rsa_store[rid] = {"private": private_pem, "public": public_pem}
        return render_template('raw_rsa.html', private_key=private_pem, public_key=public_pem, rid=rid)
    return render_template('raw_rsa.html')

@app.route('/encryption/download_raw_private')
def download_raw_private():
    rid = request.args.get('rid')
    if rid in raw_rsa_store:
        return Response(raw_rsa_store[rid]['private'], mimetype='application/x-pem-file',
                        headers={"Content-Disposition": f"attachment;filename={rid}_rsa_private.pem"})
    return "Key not found", 404

@app.route('/encryption/download_raw_public')
def download_raw_public():
    rid = request.args.get('rid')
    if rid in raw_rsa_store:
        return Response(raw_rsa_store[rid]['public'], mimetype='text/plain',
                        headers={"Content-Disposition": f"attachment;filename={rid}_rsa_public.pub"})
    return "Key not found", 404

@app.route('/encryption/rsa_hand', methods=['GET', 'POST'])
def rsa_hand():
    if request.method == 'POST':
        try:
            p = int(request.form.get('p'))
            q = int(request.form.get('q'))
        except Exception:
            return render_template('rsa_hand.html', error="Invalid input")
        message = request.form.get('message')
        def is_prime(n):
            if n < 2:
                return False
            for i in range(2, int(n**0.5)+1):
                if n % i == 0:
                    return False
            return True
        if not (is_prime(p) and is_prime(q)) or p >= 100 or q >= 100:
            return render_template('rsa_hand.html', error="p and q must be prime numbers less than 100")
        n = p * q
        if n < 128:
            return render_template('rsa_hand.html', error="n = p*q must be at least 128. Choose larger primes.")
        phi = (p - 1) * (q - 1)
        def gcd(a, b):
            while b:
                a, b = b, a % b
            return a
        e = None
        for candidate in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
            if candidate < phi and gcd(candidate, phi) == 1:
                e = candidate
                break
        if e is None:
            return render_template('rsa_hand.html', error="Could not find suitable public exponent e")
        def modinv(a, m):
            def egcd(a, b):
                if a == 0:
                    return (b, 0, 1)
                g, y, x = egcd(b % a, a)
                return (g, x - (b // a) * y, y)
            g, x, _ = egcd(a, m)
            return x % m if g == 1 else None
        d = modinv(e, phi)
        orig_numbers = [ord(c) for c in message]
        encrypted_numbers = [pow(m, e, n) for m in orig_numbers]
        decrypted_numbers = [pow(c, d, n) for c in encrypted_numbers]
        decrypted_message = ''.join(chr(num) for num in decrypted_numbers)
        return render_template('rsa_hand.html', p=p, q=q, n=n, phi=phi, e=e, d=d,
                               orig_numbers=orig_numbers, encrypted_numbers=encrypted_numbers,
                               decrypted_numbers=decrypted_numbers, message=message, decrypted_message=decrypted_message)
    return render_template('rsa_hand.html')

if __name__ == '__main__':
    app.run()