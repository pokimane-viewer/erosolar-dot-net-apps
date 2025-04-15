from flask import Flask, request, render_template, Response, send_file
import pgpy, os, uuid, secrets
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from io import BytesIO
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519, utils
from cryptography.hazmat.primitives import hashes as asym_hashes
from jinja2 import DictLoader

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
keys_store = {}
aes_store = {}
pgp_store = {}
raw_rsa_store = {}
ecc_store = {}
ed25519_store = {}

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
    <button type="button" class="navbar-toggler" data-bs-toggle="collapse" data-bs-target="#navbarNav">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav">
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/">PGP/AES/RSA Home</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/aes_encrypt">AES Encrypt</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/aes_decrypt">AES Decrypt</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/pgp_encrypt">PGP Encrypt</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/pgp_demo">PGP Download Keypair</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/raw_rsa">RSA 4096 Download Keypair</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/rsa_hand">RSA Demo</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/ecc_hand">ECC Download Keypair(4 SECP algo avail)(4 </a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/ed25519_hand">ECC Ed25519 Download Keypai </a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/x25519_hand">Diffie Hellman (X25519) Demo App</a></li>
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
    <p class="mt-3">Note: Unlike AES256 encryption keys which are temporary, your generated PGP secret key is permanently linked to your identity. To change it, generate a new key pair.</p>
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
    <p class="mt-3">Note: Your AES key is securely stored and processed only temporarily in RAM.</p>
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
    <p>Note: Generated PGP keys are permanently linked to your identity. Generate new keys to change them.</p>
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
      <div class="mb-3">
        <label class="form-label">Prime Selection Method:</label>
        <div>
          <input type="radio" id="manual" name="prime_source" value="manual" checked>
          <label for="manual">Manual Entry</label>
          <input type="radio" id="auto" name="prime_source" value="auto">
          <label for="auto">Automatic Generation</label>
        </div>
      </div>
      <div id="manual_fields">
        <div class="mb-3"><label class="form-label">Enter prime p:</label><input type="number" name="p" class="form-control"></div>
        <div class="mb-3"><label class="form-label">Enter prime q:</label><input type="number" name="q" class="form-control"></div>
      </div>
      <div id="auto_field" style="display:none;">
        <div class="mb-3"><label class="form-label">Desired bit length for primes:</label><input type="number" name="bits" class="form-control" value="512"></div>
      </div>
      <div class="mb-3"><label class="form-label">Enter a short message (max 100 characters):</label><input type="text" name="message" maxlength="100" class="form-control" required></div>
      <button type="submit" class="btn btn-primary">Run RSA Demo</button>
    </form>
    <script>
    document.getElementsByName('prime_source').forEach(function(radio) {
      radio.addEventListener('change', function() {
        if(this.value == 'manual'){
          document.getElementById('manual_fields').style.display = 'block';
          document.getElementById('auto_field').style.display = 'none';
        } else {
          document.getElementById('manual_fields').style.display = 'none';
          document.getElementById('auto_field').style.display = 'block';
        }
      });
    });
    </script>
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
    <hr>
    <p class="text-warning">RSA demo keys are for educational purposes only. Do not expose your private key publicly.</p>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

ecc_hand_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>Interactive ECC Demo</h2></div>
  <div class="card-body">
    <p>ECC (Elliptic Curve Cryptography) offers strong security with smaller key sizes. Choose a curve:
      <ul>
        <li><strong>SECP256R1:</strong> Widely used, efficient and secure.</li>
        <li><strong>SECP384R1:</strong> Higher security with larger keys.</li>
        <li><strong>SECP521R1:</strong> Maximum security with performance trade-offs.</li>
        <li><strong>SECP256K1:</strong> Popular in cryptocurrencies (e.g. Bitcoin).</li>
      </ul>
    </p>
    <form method="post">
      <div class="mb-3">
        <label class="form-label">Select ECC Curve:</label>
        <select name="curve" class="form-control" required>
          <option value="SECP256R1">SECP256R1</option>
          <option value="SECP384R1">SECP384R1</option>
          <option value="SECP521R1">SECP521R1</option>
          <option value="SECP256K1">SECP256K1</option>
        </select>
      </div>
      <div class="mb-3"><label class="form-label">Enter a message to sign:</label><input type="text" name="message" maxlength="100" class="form-control" required></div>
      <button type="submit" class="btn btn-primary">Run ECC Demo</button>
    </form>
    {% if error %}
    <p class="text-danger mt-3">{{ error }}</p>
    {% endif %}
    {% if curve %}
    <hr>
    <h3>ECC Demo Results:</h3>
    <p>Selected Curve: {{ curve }}</p>
    <h4>Private Key (PEM):</h4>
    <pre class="bg-light p-3">{{ private_key }}</pre>
    <h4>Public Key (PEM):</h4>
    <pre class="bg-light p-3">{{ public_key }}</pre>
    <h4>Message:</h4>
    <pre class="bg-light p-3">{{ message }}</pre>
    <h4>Signature (hex):</h4>
    <pre class="bg-light p-3">{{ signature }}</pre>
    <h4>Verification:</h4>
    <p>{{ verification }}</p>
    <hr>
    <h4>Download ECC Keys</h4>
    <a href="{{ base_path }}/download_ecc_private?eid={{ ecc_id }}" class="btn btn-secondary">Download ECC Private Key</a>
    <a href="{{ base_path }}/download_ecc_public?eid={{ ecc_id }}" class="btn btn-secondary">Download ECC Public Key</a>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

ed25519_hand_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>Interactive Ed25519 Demo</h2></div>
  <div class="card-body">
    <p>Ed25519 is a modern digital signature scheme using elliptic curve cryptography. It provides smaller key sizes and faster performance compared to RSA, with enhanced security against side-channel attacks.</p>
    <form method="post">
      <div class="mb-3"><label class="form-label">Enter a message to sign:</label><input type="text" name="message" maxlength="100" class="form-control" required></div>
      <button type="submit" class="btn btn-primary">Run Ed25519 Demo</button>
    </form>
    {% if message %}
    <hr>
    <h3>Ed25519 Demo Results:</h3>
    <p>Message:</p>
    <pre class="bg-light p-3">{{ message }}</pre>
    <h4>Signature (hex):</h4>
    <pre class="bg-light p-3">{{ signature }}</pre>
    <h4>Verification:</h4>
    <p>{{ verification }}</p>
    <hr>
    <h4>Download Ed25519 Keys</h4>
    <a href="{{ base_path }}/download_ed25519_private?eid={{ ed_id }}" class="btn btn-secondary">Download Private Key</a>
    <a href="{{ base_path }}/download_ed25519_public?eid={{ ed_id }}" class="btn btn-secondary">Download Public Key</a>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

x25519_hand_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>Interactive X25519 Key Exchange Demo</h2></div>
  <div class="card-body">
    <p>X25519 is an elliptic curve Diffie-Hellman key exchange algorithm that enables two parties to securely agree on a shared secret over an insecure channel. It offers better performance and smaller key sizes compared to RSA-based key exchanges.</p>
    <form method="post">
      <button type="submit" class="btn btn-primary">Run X25519 Demo</button>
    </form>
    {% if shared_secret %}
    <hr>
    <h3>X25519 Key Exchange Results:</h3>
    <h4>Party A Private Key (PEM):</h4>
    <pre class="bg-light p-3">{{ a_private }}</pre>
    <h4>Party A Public Key (PEM):</h4>
    <pre class="bg-light p-3">{{ a_public }}</pre>
    <h4>Party B Private Key (PEM):</h4>
    <pre class="bg-light p-3">{{ b_private }}</pre>
    <h4>Party B Public Key (PEM):</h4>
    <pre class="bg-light p-3">{{ b_public }}</pre>
    <h4>Shared Secret (hex):</h4>
    <pre class="bg-light p-3">{{ shared_secret }}</pre>
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
    'ecc_hand.html': ecc_hand_template,
    'ed25519_hand.html': ed25519_hand_template,
    'x25519_hand.html': x25519_hand_template,
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
        prime_source = request.form.get('prime_source', 'manual')
        message = request.form.get('message')
        def is_probable_prime(n, k=10):
            if n < 2:
                return False
            for prime in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
                if n % prime == 0:
                    return n == prime
            s, d = 0, n - 1
            while d % 2 == 0:
                s += 1
                d //= 2
            for _ in range(k):
                a = secrets.randbelow(n - 3) + 2
                x = pow(a, d, n)
                if x == 1 or x == n - 1:
                    continue
                for _ in range(s - 1):
                    x = pow(x, 2, n)
                    if x == n - 1:
                        break
                else:
                    return False
            return True
        def generate_prime(bits):
            while True:
                candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
                if is_probable_prime(candidate):
                    return candidate
        if prime_source == 'manual':
            try:
                p = int(request.form.get('p'))
                q = int(request.form.get('q'))
            except Exception:
                return render_template('rsa_hand.html', error="Invalid input")
            if not (is_probable_prime(p) and is_probable_prime(q)):
                return render_template('rsa_hand.html', error="p and q must be prime numbers")
        else:
            try:
                bits = int(request.form.get('bits'))
            except Exception:
                bits = 512
            p = generate_prime(bits)
            q = generate_prime(bits)
            while q == p:
                q = generate_prime(bits)
        n = p * q
        if n < 128:
            return render_template('rsa_hand.html', error="n = p*q must be at least 128. Choose larger primes.")
        phi = (p - 1) * (q - 1)
        def gcd(a, b):
            while b:
                a, b = b, a % b
            return a
        if phi > 65537 and gcd(65537, phi) == 1:
            e = 65537
        else:
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

@app.route('/encryption/ecc_hand', methods=['GET', 'POST'])
def ecc_hand():
    if request.method == 'POST':
        curve_name = request.form.get('curve')
        message = request.form.get('message')
        curve = None
        if curve_name == "SECP256R1":
            curve = ec.SECP256R1()
        elif curve_name == "SECP384R1":
            curve = ec.SECP384R1()
        elif curve_name == "SECP521R1":
            curve = ec.SECP521R1()
        elif curve_name == "SECP256K1":
            try:
                curve = ec.SECP256K1()
            except Exception as ex:
                return render_template('ecc_hand.html', error="SECP256K1 curve not supported", curve=curve_name)
        if not curve:
            return render_template('ecc_hand.html', error="Invalid curve selected")
        try:
            private_key = ec.generate_private_key(curve, default_backend())
            public_key = private_key.public_key()
            private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.PKCS8,
                                                    encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
            public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
            signature = private_key.sign(message.encode(), ec.ECDSA(asym_hashes.SHA256()))
            sig_hex = signature.hex()
            try:
                public_key.verify(signature, message.encode(), ec.ECDSA(asym_hashes.SHA256()))
                verification = "Signature verified successfully"
            except Exception:
                verification = "Signature verification failed"
            ecc_id = uuid.uuid4().hex
            ecc_store[ecc_id] = {"private": private_pem, "public": public_pem}
            return render_template('ecc_hand.html', curve=curve_name, message=message, private_key=private_pem,
                                   public_key=public_pem, signature=sig_hex, verification=verification, ecc_id=ecc_id)
        except Exception as ex:
            return render_template('ecc_hand.html', error="Error: " + str(ex))
    return render_template('ecc_hand.html')

@app.route('/encryption/download_ecc_private')
def download_ecc_private():
    eid = request.args.get('eid')
    if eid in ecc_store:
        return Response(ecc_store[eid]['private'], mimetype='application/x-pem-file',
                        headers={"Content-Disposition": f"attachment;filename={eid}_ecc_private.pem"})
    return "Key not found", 404

@app.route('/encryption/download_ecc_public')
def download_ecc_public():
    eid = request.args.get('eid')
    if eid in ecc_store:
        return Response(ecc_store[eid]['public'], mimetype='text/plain',
                        headers={"Content-Disposition": f"attachment;filename={eid}_ecc_public.pem"})
    return "Key not found", 404

@app.route('/encryption/ed25519_hand', methods=['GET', 'POST'])
def ed25519_hand():
    if request.method == 'POST':
        message = request.form.get('message')
        try:
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()
            signature = private_key.sign(message.encode())
            sig_hex = signature.hex()
            try:
                public_key.verify(signature, message.encode())
                verification = "Signature verified successfully"
            except Exception:
                verification = "Signature verification failed"
            ed_id = uuid.uuid4().hex
            ed25519_store[ed_id] = {"private": private_key.private_bytes(
                                            encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=serialization.NoEncryption()).decode('utf-8'),
                                     "public": public_key.public_bytes(
                                            encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')}
            return render_template('ed25519_hand.html', message=message, signature=sig_hex, verification=verification, ed_id=ed_id)
        except Exception as ex:
            return render_template('ed25519_hand.html', error="Error: " + str(ex))
    return render_template('ed25519_hand.html')

@app.route('/encryption/download_ed25519_private')
def download_ed25519_private():
    eid = request.args.get('eid')
    if eid in ed25519_store:
        return Response(ed25519_store[eid]['private'], mimetype='application/x-pem-file',
                        headers={"Content-Disposition": f"attachment;filename={eid}_ed25519_private.pem"})
    return "Key not found", 404

@app.route('/encryption/download_ed25519_public')
def download_ed25519_public():
    eid = request.args.get('eid')
    if eid in ed25519_store:
        return Response(ed25519_store[eid]['public'], mimetype='text/plain',
                        headers={"Content-Disposition": f"attachment;filename={eid}_ed25519_public.pem"})
    return "Key not found", 404

@app.route('/encryption/x25519_hand', methods=['GET', 'POST'])
def x25519_hand():
    if request.method == 'POST':
        a_private = x25519.X25519PrivateKey.generate()
        a_public = a_private.public_key()
        b_private = x25519.X25519PrivateKey.generate()
        b_public = b_private.public_key()
        shared_secret = a_private.exchange(b_public).hex()
        a_private_pem = a_private.private_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PrivateFormat.PKCS8,
                                                 encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
        a_public_pem = a_public.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        b_private_pem = b_private.private_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PrivateFormat.PKCS8,
                                                 encryption_algorithm=serialization.NoEncryption()).decode('utf-8')
        b_public_pem = b_public.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')
        return render_template('x25519_hand.html', shared_secret=shared_secret,
                               a_private=a_private_pem, a_public=a_public_pem,
                               b_private=b_private_pem, b_public=b_public_pem)
    return render_template('x25519_hand.html')

if __name__ == '__main__':
    app.run()