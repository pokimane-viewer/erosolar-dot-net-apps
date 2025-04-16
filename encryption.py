from flask import Flask, request, render_template, Response, send_file, jsonify
import pgpy, os, uuid, secrets, hashlib, base64
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as crypto_hashes, serialization
from io import BytesIO
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519, utils
from cryptography.hazmat.primitives import hashes as asym_hashes
from jinja2 import DictLoader
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['UPLOAD_FOLDER'] = '/tmp/flask_uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

keys_store = {}
aes_store = {}
pgp_store = {}
raw_rsa_store = {}
ecc_store = {}
ed25519_store = {}

MY_PGP_PUBLIC_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----

xsFNBGf+9ZUBEACrKybopJYYpml3SwVlVwTe0w5klWwsN5Z8Dn70zdNfkRGROFnX
Bucfog7xXGvuBaCVQywT9ZCNx68GoQc2E5e7oIj+wnpGhd62ZgolweU3QiRc83si
BOAV2CwjEhyH3/6jG/n0y8ZOGVh5n0PuWXvHFayMRwmVCxuJwXFFTwPVEiWb4Xzz
NmraXbCA9SkZwsvfV6c8vInPq4g0db/B+YYiG6x4UKRZNmoTuyTJHG4yjsQhIMR9
5qih9xvTXcSKlsjTTETi9GBfstTmSvTcigHGZLOUg+8H0FpyVJPeTEuSda25zT9l
0rQOHpyrwPknEej+K0bjaPErdy5o9Ksvzr/j+A7RuFN3Z8FIMZ/O5nr085fCnA23
WF47Aj6/jRxf+MV6QFOLvJm23QBClEC0vxWhzsw1hZSpEHClMJkg7NXFNPrwNCpj
z70mXAm9jwsdw+VBg6xrsYoDKRjhUzYTw+wP4ed4fQBrd8F7z/mC38M538A2pf5z
Cl8ioEuzDMtZXGJr8QEH3IjYEqWmeE+6HoxZL6ftqOZGLKQChnsvTIfrsYkoO2pr
DpQ1Bj+1AJ+huap54VOTzxLp19RILW+ApozzeEEmubSoWpVvHVerTJ79ocdiuiir
I0dWs6trF7hFLTrFGuLPf7jh6a796mlIqzCQUkBaa3G3r9AG7BdosU0YQwARAQAB
zVNCbyBTaGFuZyAoSSBtZWFuIHdpdGggc29tZSB3b3JrLCBJIGJldCBJIGNvdWxk
IGRvIFNNQnYyKSA8cHNldWRvLm5zYUBwZXRhbG1haWwuY29tPsLBggQTAQgALAUC
Z/71lwIbDgILCQIVCAIWAAIeARYhBLnwDqk7+RetWDXoQ5v/UyE1ajt9AAoJEJv/
UyE1ajt9zkgQAKW0DeSdVbA6M8zMTa7db4M3HqkZ0Og2FVIqwr5uGSm7NkFCbWD1
PJPg2fk4raKSdJMLflsGu15EgjjkLzqKCVsr42hy0Z/saDsp6xlGcCbGrgzGmlak
NbJev5XZV7Fm/YlicmTRpPdRSdqO6w3s5d0EljI3ZcN/26THBXGbfCiTJrpNciQ4
gULRprU/mr4zr/Wtq8GHGil9WQ80rllavcVlWG2WYMjP9QXgv5Ke61cCyvOqsB+E
jc0RVg9BnLyRGIDOEq888zG8ZBcXe7d2DR4/GE5xHfSWc9ZHJntgViqQzOCe6ONS
QdrfEm4kW/wFg1K7DKEaSQu/W1R8InVn4jB9manacfZNbUsploENKdSBsyKzx0xD
lCC67V4Jmpw99oaJ87+EYfs6jGlPANfypF38F2EikPnQ2nd2AyoMjlli3u5bti3D
1/5SePxs6En4dNvm+ZG3gRqQ4w1FDgRA7Mr5/AO3y5mq8e06VeuRsQCUXTFRABsC
lqNR0yMRwbgQNXHivWuu8g03TN8SDRffqBASqR9dZtpiX6IXnq6A4Py5pBonexCd
FbVxStoMJq44tshUTU9WprcsM7h0Zy0jhGkxfXrNOrhsEQEmFjOWB6xVX86NTEh0
Twe6v9vKNqg6XWxYzYdMigxU7VM2MgP1sOwjpofUNGg2TB5Bkp2S2TRa
=e9lh
-----END PGP PUBLIC KEY BLOCK-----"""

try:
    MY_PUBLIC_PGP_KEY_OBJ, _ = pgpy.PGPKey.from_blob(MY_PGP_PUBLIC_KEY)
except Exception:
    MY_PUBLIC_PGP_KEY_OBJ = None

@app.context_processor
def inject_base_path():
    return dict(base_path="/encryption")

base_template = '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title | default("Encryption & Key Generation") }}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    pre { white-space: pre-wrap; word-wrap: break-word; }
    .copy-btn { cursor: pointer; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ base_path }}/">Encryption & KeyGen</a>
    <button type="button" class="navbar-toggler" data-bs-toggle="collapse" data-bs-target="#navbarNav">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
      <ul class="navbar-nav">
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/my_pgp">My PGP Key</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ base_path }}/hashing">Hashing</a></li>
        <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" id="navbarKeyGen" role="button" data-bs-toggle="dropdown" aria-expanded="false">
              Key Generation
            </a>
            <ul class="dropdown-menu" aria-labelledby="navbarKeyGen">
                <li><a class="dropdown-item" href="{{ base_path }}/">PGP Keypair (PGPy)</a></li>
                <li><a class="dropdown-item" href="{{ base_path }}/raw_rsa">RSA Keypair (SSH)</a></li>
                <li><a class="dropdown-item" href="{{ base_path }}/ecc_hand">ECDSA Keypair (SSH)</a></li>
                <li><a class="dropdown-item" href="{{ base_path }}/ed25519_hand">Ed25519 Keypair (SSH)</a></li>
            </ul>
        </li>
        <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" id="navbarEncrypt" role="button" data-bs-toggle="dropdown" aria-expanded="false">
              Encryption
            </a>
            <ul class="dropdown-menu" aria-labelledby="navbarEncrypt">
                <li><a class="dropdown-item" href="{{ base_path }}/aes_encrypt">AES Encrypt File</a></li>
                <li><a class="dropdown-item" href="{{ base_path }}/aes_decrypt">AES Decrypt File</a></li>
                <li><a class="dropdown-item" href="{{ base_path }}/pgp_encrypt">PGP Encrypt Msg</a></li>
            </ul>
        </li>
         <li class="nav-item dropdown">
            <a class="nav-link dropdown-toggle" href="#" id="navbarDemo" role="button" data-bs-toggle="dropdown" aria-expanded="false">
              Demos
            </a>
            <ul class="dropdown-menu" aria-labelledby="navbarDemo">
                <li><a class="dropdown-item" href="{{ base_path }}/pgp_demo">PGP Encrypt/Decrypt Demo</a></li>
                <li><a class="dropdown-item" href="{{ base_path }}/rsa_hand">RSA Math Demo</a></li>
                <li><a class="dropdown-item" href="{{ base_path }}/x25519_hand">X25519 Key Exchange</a></li>
            </ul>
        </li>
      </ul>
    </div>
  </div>
</nav>
<div class="container">
  {% block content %}{% endblock %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
function copyToClipboard(elementId, buttonElement) {
  const textToCopy = document.getElementById(elementId).innerText;
  navigator.clipboard.writeText(textToCopy).then(function() {
    const originalText = buttonElement.innerHTML;
    buttonElement.textContent = 'Copied!';
    setTimeout(() => { buttonElement.innerHTML = originalText; }, 2000);
  }, function(err) {
    console.error('Async: Could not copy text: ', err);
    alert('Failed to copy text.');
  });
}
</script>
</body>
</html>
'''

index_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>Generate RSA4096 PGP Key Pair (PGPy)</h2></div>
  <div class="card-body">
    <p>Generate your own PGP key pair for secure communication.</p>
    <form method="post">
      <div class="mb-3"><label class="form-label">Name:</label><input type="text" name="name" class="form-control" required></div>
      <div class="mb-3"><label class="form-label">Email:</label><input type="email" name="email" class="form-control" required></div>
      <div class="mb-3"><label class="form-label">Comment:</label><input type="text" name="comment" class="form-control"></div>
      <div class="mb-3"><label class="form-label">Passphrase (Optional but Recommended):</label><input type="password" name="passphrase" class="form-control"></div>
      <button type="submit" class="btn btn-primary">Generate PGP Key Pair</button>
    </form>
    <p class="mt-3">Note: Unlike temporary AES keys, your generated PGP secret key is intended for long-term use. Protect it carefully.</p>
    {% if public_key %}
    <hr>
    <h3>Generated PGP Public Key</h3>
    <pre id="publicKeyBlock" class="bg-light p-3">{{ public_key }}</pre>
    <button class="btn btn-outline-secondary btn-sm copy-btn" onclick="copyToClipboard('publicKeyBlock', this)">Copy Key</button>
    <a href="{{ base_path }}/download_public?name={{ filename }}" class="btn btn-secondary ms-2">Download Public Key (.asc)</a>
    <a href="{{ base_path }}/download_private?name={{ filename }}" class="btn btn-secondary ms-2">Download Private Key (.asc)</a>
    <h4 class="mt-3">Using Your PGP Keys</h4>
    <p>Import the downloaded private key into your PGP client (e.g., GPG Suite, Kleopatra, <code>gpg --import {{ filename }}_private.asc</code>). Share the public key (.asc file or the text above) with others so they can encrypt messages for you.</p>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

aes_encrypt_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>AES256-GCM Encrypt File</h2></div>
  <div class="card-body">
    <form method="post" enctype="multipart/form-data">
      <div class="mb-3"><label class="form-label">Select file to encrypt:</label><input type="file" name="file" class="form-control" required></div>
      <div class="mb-3"><label class="form-label">Password:</label><input type="password" name="password" class="form-control" required></div>
      <button type="submit" class="btn btn-primary">Encrypt File</button>
    </form>
    <p class="mt-3">Note: Uses AES-256-GCM with PBKDF2-SHA256 (390k iterations) for key derivation. The password is not stored.</p>
    {% if encrypted %}
    <hr>
    <h3>Encrypted File Ready</h3>
    <a href="{{ base_path }}/download_encrypted?fname={{ filename }}" class="btn btn-secondary">Download Encrypted File (.enc)</a>
    {% endif %}
    {% if error %}
    <p class="text-danger mt-3">{{ error }}</p>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

aes_decrypt_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>AES256-GCM Decrypt File</h2></div>
  <div class="card-body">
    <form method="post" enctype="multipart/form-data">
      <div class="mb-3"><label class="form-label">Select encrypted file (.enc):</label><input type="file" name="file" class="form-control" required></div>
      <div class="mb-3"><label class="form-label">Password:</label><input type="password" name="password" class="form-control" required></div>
      <button type="submit" class="btn btn-primary">Decrypt File</button>
    </form>
    {% if error %}<p class="text-danger mt-3">{{ error }}</p>{% endif %}
  </div>
</div>
{% endblock %}
'''

pgp_encrypt_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>PGP Encrypt Message For Recipient</h2></div>
  <div class="card-body">
    <p>Encrypt a message using someone else's PGP public key.</p>
    <form method="post">
      <div class="mb-3"><label class="form-label">Recipient's PGP Public Key (ASCII Armored):</label><textarea name="recipient_key" rows="10" class="form-control" required placeholder="-----BEGIN PGP PUBLIC KEY BLOCK----- ..."></textarea></div>
      <div class="mb-3"><label class="form-label">Message to Encrypt:</label><textarea name="message" rows="5" class="form-control" required></textarea></div>
      <button type="submit" class="btn btn-primary">Encrypt Message</button>
    </form>
    {% if encrypted_message %}
    <hr>
    <h3>Encrypted PGP Message</h3>
    <pre id="encryptedMessageBlock" class="bg-light p-3">{{ encrypted_message }}</pre>
    <button class="btn btn-outline-secondary btn-sm copy-btn" onclick="copyToClipboard('encryptedMessageBlock', this)">Copy Encrypted Message</button>
    <a href="{{ base_path }}/download_pgp?fname={{ filename }}" class="btn btn-secondary ms-2">Download Encrypted Message (.asc)</a>
    {% endif %}
    {% if error %}
    <p class="text-danger mt-3">{{ error }}</p>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

pgp_demo_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>PGP Encryption/Decryption Demo</h2></div>
  <div class="card-body">
    <p>This generates a temporary PGP key pair, encrypts a message with the public key, and then decrypts it with the private key.</p>
    <form method="post">
      <div class="mb-3"><label class="form-label">Enter a short message:</label><textarea name="demo_message" rows="3" class="form-control" required>Test Message</textarea></div>
      <button type="submit" class="btn btn-primary">Run PGP Demo</button>
    </form>
    {% if public_key %}
    <hr>
    <h3>Generated Public Key (Temporary)</h3>
    <pre class="bg-light p-3">{{ public_key }}</pre>
    <h3>Generated Private Key (Temporary, Unprotected)</h3>
    <pre class="bg-light p-3">{{ private_key }}</pre>
    <h3>Original Message</h3>
    <pre class="bg-light p-3">{{ original_message }}</pre>
    <h3>Encrypted Message (Using Public Key)</h3>
    <pre class="bg-light p-3">{{ encrypted_message }}</pre>
    <h3>Decrypted Message (Using Private Key)</h3>
    <pre class="bg-light p-3">{{ decrypted_message }}</pre>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

raw_rsa_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>Generate RSA Key Pair (SSH Compatible)</h2></div>
  <div class="card-body">
    <p>Generate an RSA key pair suitable for SSH authentication.</p>
    <form method="post">
      <div class="mb-3">
        <label for="key_size" class="form-label">Select Key Size (bits):</label>
        <select class="form-select" id="key_size" name="key_size">
          <option value="2048">2048 (Standard Minimum)</option>
          <option value="3072">3072</option>
          <option value="4096" selected>4096 (Recommended)</option>
        </select>
      </div>
      <button type="submit" class="btn btn-primary">Generate RSA Key Pair</button>
    </form>
    {% if private_key %}
    <hr>
    <h3>Generated Private Key (PEM Format)</h3>
    <pre id="sshPrivateKey" class="bg-light p-3">{{ private_key }}</pre>
    <button class="btn btn-outline-secondary btn-sm copy-btn" onclick="copyToClipboard('sshPrivateKey', this)">Copy Private Key</button>
    <a href="{{ base_path }}/download_raw_private?rid={{ rid }}" class="btn btn-secondary ms-2">Download Private Key</a>

    <h3 class="mt-3">Generated Public Key (OpenSSH Format)</h3>
    <pre id="sshPublicKey" class="bg-light p-3">{{ public_key }}</pre>
    <button class="btn btn-outline-secondary btn-sm copy-btn" onclick="copyToClipboard('sshPublicKey', this)">Copy Public Key</button>
    <a href="{{ base_path }}/download_raw_public?rid={{ rid }}" class="btn btn-secondary ms-2">Download Public Key</a>

    <h4 class="mt-4">Using Your SSH Keys</h4>
    <p>Follow these steps to use your new key pair for SSH:</p>
    <ol>
        <li><strong>Download both keys.</strong></li>
        <li><strong>Move the private key:</strong> Place the downloaded private key file (the one <em>without</em> <code>.pub</code>) into your <code>~/.ssh/</code> directory (on Linux/macOS/WSL) or <code>C:\\Users\\YourUsername\\.ssh\\</code> (on Windows). Rename it if desired (e.g., <code>id_rsa_{{ key_size }}</code> or simply <code>id_rsa</code> if it's your primary key).
           <br>Example (Linux/macOS): <code>mv ~/Downloads/id_rsa_{{ key_size }}_{{ rid[:8]}} ~/.ssh/id_rsa_{{ key_size }}</code></li>
        <li><strong>Set permissions (Crucial!):</strong> Restrict permissions on the private key file so only you can read it.
           <br>Linux/macOS/WSL: <code>chmod 600 ~/.ssh/id_rsa_{{ key_size }}</code>
           <br>Windows (using Explorer): Right-click file -> Properties -> Security -> Advanced -> Disable inheritance -> Remove all users except yourself -> Ensure your user has Full Control.</li>
        <li><strong>Move the public key:</strong> Place the downloaded public key file (the one <em>with</em> <code>.pub</code>) into the same <code>~/.ssh/</code> directory. Its permissions are less critical (usually 644). Rename it to match the private key name plus <code>.pub</code> (e.g., <code>id_rsa_{{ key_size }}.pub</code>).
           <br>Example (Linux/macOS): <code>mv ~/Downloads/id_rsa_{{ key_size }}_{{ rid[:8]}}.pub ~/.ssh/id_rsa_{{ key_size }}.pub</code></li>
        <li><strong>Add public key to server:</strong> Copy the <em>content</em> of the public key file (<code>{{ public_key }}</code>) and add it as a new line to the <code>~/.ssh/authorized_keys</code> file on the server you want to connect to.</li>
        <li><strong>Connect:</strong> Use SSH, specifying the private key if it's not the default <code>id_rsa</code>:
           <br><code>ssh -i ~/.ssh/id_rsa_{{ key_size }} user@hostname</code></li>
    </ol>
    <p class="text-danger"><strong>Warning:</strong> Protect your private key. Anyone who obtains it can impersonate you on servers where the corresponding public key is authorized.</p>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

rsa_hand_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>Interactive RSA Demo (Manual/Small Primes)</h2></div>
  <div class="card-body">
    <p>This demo illustrates the core mathematical steps of RSA encryption and decryption using manually entered small prime numbers or slightly larger generated ones.</p>
    <p class="alert alert-info">For generating actual secure SSH keys, please use the "RSA Keypair (SSH)", "ECDSA Keypair (SSH)", or "Ed25519 Keypair (SSH)" options from the menu.</p>
    <form method="post">
      <div class="mb-3">
        <label class="form-label">Prime Selection Method:</label>
        <div>
          <input type="radio" id="manual" name="prime_source" value="manual" checked>
          <label for="manual">Manual Entry (Small Primes)</label>
        </div>
         <div>
          <input type="radio" id="auto" name="prime_source" value="auto">
          <label for="auto">Generate Primes (Small Bit Length)</label>
        </div>
      </div>
      <div id="manual_fields">
        <div class="mb-3"><label class="form-label">Enter prime p (e.g., 61):</label><input type="number" name="p" class="form-control"></div>
        <div class="mb-3"><label class="form-label">Enter prime q (e.g., 53):</label><input type="number" name="q" class="form-control"></div>
      </div>
      <div id="auto_field" style="display:none;">
        <div class="mb-3"><label class="form-label">Bit length per prime (e.g., 10-16 bits):</label><input type="number" name="bits" class="form-control" value="12" min="8" max="32"></div>
      </div>
      <div class="mb-3"><label class="form-label">Enter a short message:</label><input type="text" name="message" maxlength="100" class="form-control" required value="Hello RSA"></div>
      <button type="submit" class="btn btn-primary">Run RSA Demo</button>
    </form>
    <script>
    document.getElementsByName('prime_source').forEach(function(radio) {
      radio.addEventListener('change', function() {
        if(this.value == 'manual'){
          document.getElementById('manual_fields').style.display = 'block';
          document.getElementById('auto_field').style.display = 'none';
          document.querySelector('input[name="p"]').required = true;
          document.querySelector('input[name="q"]').required = true;
          document.querySelector('input[name="bits"]').required = false;
        } else {
          document.getElementById('manual_fields').style.display = 'none';
          document.getElementById('auto_field').style.display = 'block';
          document.querySelector('input[name="p"]').required = false;
          document.querySelector('input[name="q"]').required = false;
          document.querySelector('input[name="bits"]').required = true;
        }
      });
    });
    // Initial setup based on checked radio
    if (document.getElementById('auto').checked) {
        document.getElementById('manual_fields').style.display = 'none';
        document.getElementById('auto_field').style.display = 'block';
        document.querySelector('input[name="p"]').required = false;
        document.querySelector('input[name="q"]').required = false;
        document.querySelector('input[name="bits"]').required = true;
    } else {
        document.getElementById('manual_fields').style.display = 'block';
        document.getElementById('auto_field').style.display = 'none';
        document.querySelector('input[name="p"]').required = true;
        document.querySelector('input[name="q"]').required = true;
        document.querySelector('input[name="bits"]').required = false;
    }
    </script>
    {% if error %}
    <p class="alert alert-danger mt-3">{{ error }}</p>
    {% endif %}
    {% if p %}
    <hr>
    <h3>RSA Parameters:</h3>
    <p style="overflow-wrap: break-word;">Prime p: {{ p }}</p>
    <p style="overflow-wrap: break-word;">Prime q: {{ q }}</p>
    <p style="overflow-wrap: break-word;">Modulus n = p * q: {{ n }}</p>
    <p style="overflow-wrap: break-word;">Totient &Phi;(n) = (p-1)*(q-1): {{ phi }}</p>
    <p style="overflow-wrap: break-word;">Public exponent e: {{ e }}</p>
    <p style="overflow-wrap: break-word;">Private exponent d: {{ d }}</p>
    <h3>Encryption Process:</h3>
    <p>Original Message: "{{ message }}"</p>
    <p style="overflow-wrap: break-word;">Message as numbers (ASCII/UTF-8 bytes): {{ orig_numbers }}</p>
    <p style="overflow-wrap: break-word;">Encrypted numbers (m<sup>e</sup> mod n): {{ encrypted_numbers }}</p>
    <h3>Decryption Process:</h3>
    <p style="overflow-wrap: break-word;">Decrypted numbers (c<sup>d</sup> mod n): {{ decrypted_numbers }}</p>
    <p>Decrypted Message: "{{ decrypted_message }}"</p>
    <hr>
    <p class="alert alert-warning">RSA demo keys are for educational purposes only. The prime numbers used here are far too small for real security.</p>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

ecc_hand_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>Generate ECDSA Key Pair (SSH Compatible)</h2></div>
  <div class="card-body">
    <p>Generate an ECDSA (Elliptic Curve Digital Signature Algorithm) key pair using curves commonly supported by OpenSSH.</p>
    <form method="post">
      <div class="mb-3">
        <label class="form-label">Select ECC Curve:</label>
        <select name="curve" class="form-control" required>
          <option value="SECP256R1" selected>SECP256R1 (nistp256 - Recommended)</option>
          <option value="SECP384R1">SECP384R1 (nistp384)</option>
          <option value="SECP521R1">SECP521R1 (nistp521)</option>
        </select>
      </div>
      <button type="submit" class="btn btn-primary">Generate ECDSA Key Pair</button>
    </form>
    {% if error %}
    <p class="alert alert-danger mt-3">{{ error }}</p>
    {% endif %}
    {% if curve %}
    <hr>
    <h3>ECDSA Key Pair Results ({{ curve }} / {{ ssh_curve_name }}):</h3>
    <h4>Generated Private Key (OpenSSH PEM Format):</h4>
    <pre id="eccPrivateKey" class="bg-light p-3">{{ private_key_openssh }}</pre>
    <button class="btn btn-outline-secondary btn-sm copy-btn" onclick="copyToClipboard('eccPrivateKey', this)">Copy Private Key</button>
    <a href="{{ base_path }}/download_ecc_private?eid={{ ecc_id }}" class="btn btn-secondary ms-2">Download Private Key</a>

    <h4 class="mt-3">Generated Public Key (OpenSSH Format):</h4>
    <pre id="eccPublicKey" class="bg-light p-3">{{ public_key_openssh }}</pre>
    <button class="btn btn-outline-secondary btn-sm copy-btn" onclick="copyToClipboard('eccPublicKey', this)">Copy Public Key</button>
    <a href="{{ base_path }}/download_ecc_public?eid={{ ecc_id }}" class="btn btn-secondary ms-2">Download Public Key</a>

    <h4 class="mt-4">Using Your SSH Keys</h4>
    <p>Follow these steps to use your new key pair for SSH:</p>
    <ol>
        <li><strong>Download both keys.</strong></li>
        <li><strong>Move the private key:</strong> Place the downloaded private key file into your <code>~/.ssh/</code> directory. Rename it appropriately (e.g., <code>id_ecdsa_{{ ssh_curve_name }}</code> or <code>id_ecdsa</code>).
           <br>Example (Linux/macOS): <code>mv ~/Downloads/id_ecdsa_{{ ssh_curve_name }}_{{ ecc_id[:8] }} ~/.ssh/id_ecdsa_{{ ssh_curve_name }}</code></li>
        <li><strong>Set permissions (Crucial!):</strong> Restrict permissions on the private key file.
           <br>Linux/macOS/WSL: <code>chmod 600 ~/.ssh/id_ecdsa_{{ ssh_curve_name }}</code>
           <br>Windows: Use Explorer properties (Security tab) to restrict access to only your user.</li>
        <li><strong>Move the public key:</strong> Place the downloaded public key file into <code>~/.ssh/</code>. Rename it to match the private key name plus <code>.pub</code> (e.g., <code>id_ecdsa_{{ ssh_curve_name }}.pub</code>).
           <br>Example (Linux/macOS): <code>mv ~/Downloads/id_ecdsa_{{ ssh_curve_name }}_{{ ecc_id[:8] }}.pub ~/.ssh/id_ecdsa_{{ ssh_curve_name }}.pub</code></li>
        <li><strong>Add public key to server:</strong> Copy the <em>content</em> of the public key file (<code>{{ public_key_openssh }}</code>) and add it as a new line to the <code>~/.ssh/authorized_keys</code> file on the target server.</li>
        <li><strong>Connect:</strong> Use SSH, specifying the private key if needed:
           <br><code>ssh -i ~/.ssh/id_ecdsa_{{ ssh_curve_name }} user@hostname</code></li>
    </ol>
     <p class="text-danger"><strong>Warning:</strong> Protect your private key. Anyone who obtains it can impersonate you.</p>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

ed25519_hand_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>Generate Ed25519 Key Pair (SSH Compatible)</h2></div>
  <div class="card-body">
    <p>Generate an Ed25519 key pair. Ed25519 is a modern, fast, and secure elliptic curve signature scheme widely supported by SSH.</p>
    <form method="post">
      <button type="submit" class="btn btn-primary">Generate Ed25519 Key Pair</button>
    </form>
    {% if error %}
    <p class="alert alert-danger mt-3">{{ error }}</p>
    {% endif %}
    {% if private_key_openssh %}
    <hr>
    <h3>Ed25519 Key Pair Results:</h3>
    <h4>Generated Private Key (OpenSSH PEM Format):</h4>
    <pre id="edPrivateKey" class="bg-light p-3">{{ private_key_openssh }}</pre>
    <button class="btn btn-outline-secondary btn-sm copy-btn" onclick="copyToClipboard('edPrivateKey', this)">Copy Private Key</button>
    <a href="{{ base_path }}/download_ed25519_private?eid={{ ed_id }}" class="btn btn-secondary ms-2">Download Private Key</a>

    <h4 class="mt-3">Generated Public Key (OpenSSH Format):</h4>
    <pre id="edPublicKey" class="bg-light p-3">{{ public_key_openssh }}</pre>
    <button class="btn btn-outline-secondary btn-sm copy-btn" onclick="copyToClipboard('edPublicKey', this)">Copy Public Key</button>
    <a href="{{ base_path }}/download_ed25519_public?eid={{ ed_id }}" class="btn btn-secondary ms-2">Download Public Key</a>

    <h4 class="mt-4">Using Your SSH Keys</h4>
    <p>Follow these steps to use your new key pair for SSH:</p>
    <ol>
        <li><strong>Download both keys.</strong></li>
        <li><strong>Move the private key:</strong> Place the downloaded private key file into your <code>~/.ssh/</code> directory. Rename it appropriately (e.g., <code>id_ed25519</code>).
           <br>Example (Linux/macOS): <code>mv ~/Downloads/id_ed25519_{{ ed_id[:8] }} ~/.ssh/id_ed25519</code></li>
        <li><strong>Set permissions (Crucial!):</strong> Restrict permissions on the private key file.
           <br>Linux/macOS/WSL: <code>chmod 600 ~/.ssh/id_ed25519</code>
           <br>Windows: Use Explorer properties (Security tab) to restrict access to only your user.</li>
        <li><strong>Move the public key:</strong> Place the downloaded public key file into <code>~/.ssh/</code>. Rename it to match the private key name plus <code>.pub</code> (e.g., <code>id_ed25519.pub</code>).
           <br>Example (Linux/macOS): <code>mv ~/Downloads/id_ed25519_{{ ed_id[:8] }}.pub ~/.ssh/id_ed25519.pub</code></li>
        <li><strong>Add public key to server:</strong> Copy the <em>content</em> of the public key file (<code>{{ public_key_openssh }}</code>) and add it as a new line to the <code>~/.ssh/authorized_keys</code> file on the target server.</li>
        <li><strong>Connect:</strong> Use SSH, specifying the private key if needed (though often auto-detected if named <code>id_ed25519</code>):
           <br><code>ssh -i ~/.ssh/id_ed25519 user@hostname</code></li>
    </ol>
    <p class="text-danger"><strong>Warning:</strong> Protect your private key. Anyone who obtains it can impersonate you.</p>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

x25519_hand_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>X25519 Key Exchange Demo</h2></div>
  <div class="card-body">
    <p>X25519 is an elliptic curve Diffie-Hellman (ECDH) function using Curve25519. It allows two parties (Alice and Bob) to establish a shared secret over an insecure channel. This demo generates two key pairs and computes the shared secret from both perspectives.</p>
    <p class="alert alert-info">Note: X25519 is used for key <em>agreement</em>, not signing like RSA, ECDSA, or Ed25519 SSH keys. These keys are not directly used for SSH authentication in the same way.</p>
    <form method="post">
      <button type="submit" class="btn btn-primary">Run X25519 Demo</button>
    </form>
    {% if error %}
       <p class="alert alert-danger mt-3">{{ error }}</p>
    {% endif %}
    {% if shared_secret_a %}
    <hr>
    <h3>X25519 Key Exchange Results:</h3>
    <p>Two independent X25519 key pairs are generated (Party A and Party B).</p>
    <h4>Party A Private Key (PEM - PKCS8):</h4>
    <pre class="bg-light p-3">{{ a_private }}</pre>
    <h4>Party A Public Key (PEM - SubjectPublicKeyInfo):</h4>
    <pre class="bg-light p-3">{{ a_public }}</pre>
    <h4>Party B Private Key (PEM - PKCS8):</h4>
    <pre class="bg-light p-3">{{ b_private }}</pre>
    <h4>Party B Public Key (PEM - SubjectPublicKeyInfo):</h4>
    <pre class="bg-light p-3">{{ b_public }}</pre>
    <hr/>
    <h4>Shared Secret Calculation:</h4>
    <p>Party A computes the shared secret using <strong>A's private key</strong> and <strong>B's public key</strong>.</p>
    <p>Party B computes the shared secret using <strong>B's private key</strong> and <strong>A's public key</strong>.</p>
    <p>Shared Secret derived by A (hex):</p>
    <pre class="bg-light p-3" style="overflow-wrap: break-word;">{{ shared_secret_a }}</pre>
    <p>Shared Secret derived by B (hex):</p>
    <pre class="bg-light p-3" style="overflow-wrap: break-word;">{{ shared_secret_b }}</pre>
    <p class="mt-3"><strong>Result:</strong> Do both parties compute the same shared secret?
       <span class="badge bg-{{ 'success' if shared_secret_a == shared_secret_b else 'danger' }}">
       {{ "Yes" if shared_secret_a == shared_secret_b else "No" }}
       </span>
    </p>
    <p>This shared secret can then be used as input to a KDF (Key Derivation Function) to generate symmetric keys for encryption.</p>
    {% endif %}
  </div>
</div>
{% endblock %}
'''

my_pgp_template = '''{% extends "base.html" %}
{% block content %}
<div class="card mb-4">
    <div class="card-header"><h2>My PGP Public Key</h2></div>
    <div class="card-body">
        <p>Use this key to encrypt messages intended for me or to verify signatures I have made.</p>
        <pre id="myPublicKeyBlock" class="bg-light p-3">{{ my_public_key }}</pre>
        <button class="btn btn-outline-secondary btn-sm copy-btn" onclick="copyToClipboard('myPublicKeyBlock', this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard" viewBox="0 0 16 16">
              <path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/>
              <path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/>
            </svg> Copy Key
        </button>
    </div>
</div>

<div class="card mb-4">
    <div class="card-header"><h2>Encrypt a Message For Me</h2></div>
    <div class="card-body">
        <form method="post">
            <input type="hidden" name="action" value="encrypt">
            <div class="mb-3">
                <label for="messageToEncrypt" class="form-label">Your Message:</label>
                <textarea id="messageToEncrypt" name="message_to_encrypt" rows="5" class="form-control" required placeholder="Enter the message you want to encrypt..."></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Encrypt Message</button>
        </form>
        {% if encrypted_for_me %}
        <hr>
        <h4>Encrypted Message:</h4>
        <pre id="encryptedForMeBlock" class="bg-light p-3">{{ encrypted_for_me }}</pre>
        <button class="btn btn-outline-secondary btn-sm copy-btn" onclick="copyToClipboard('encryptedForMeBlock', this)">Copy Encrypted Message</button>
        {% endif %}
        {% if encrypt_error %}
        <p class="text-danger mt-3">Encryption Error: {{ encrypt_error }}</p>
        {% endif %}
    </div>
</div>

<div class="card">
    <div class="card-header"><h2>Verify a Message Signed By Me</h2></div>
    <div class="card-body">
        <form method="post">
            <input type="hidden" name="action" value="verify">
            <div class="mb-3">
                <label for="signedMessage" class="form-label">Signed Message:</label>
                <textarea id="signedMessage" name="signed_message" rows="10" class="form-control" required placeholder="Paste the full signed PGP message here (including -----BEGIN PGP SIGNED MESSAGE----- ... -----END PGP SIGNATURE-----)"></textarea>
            </div>
            <button type="submit" class="btn btn-primary">Verify Signature</button>
        </form>
        {% if verification_result is not none %}
        <hr>
        <h4>Verification Result:</h4>
        {% if verification_result %}
        <div class="alert alert-success" role="alert">
            <strong>Success!</strong> The signature is valid and was made by my key.
        </div>
        {% else %}
        <div class="alert alert-danger" role="alert">
            <strong>Failed!</strong> The signature is invalid or could not be verified with my key.
        </div>
        {% endif %}
        {% if verified_message_content %}
        <h5>Original Message Content:</h5>
        <pre class="bg-light p-2">{{ verified_message_content }}</pre>
        {% endif %}
        {% endif %}
        {% if verify_error %}
        <p class="text-danger mt-3">Verification Error: {{ verify_error }}</p>
        {% endif %}
    </div>
</div>
{% endblock %}
'''

hashing_template = '''{% extends "base.html" %}
{% block content %}
<div class="card">
  <div class="card-header"><h2>Calculate MD5 / SHA256 Hash</h2></div>
  <div class="card-body">
    <form method="post" enctype="multipart/form-data" id="hashForm">
      <div class="mb-3">
        <label class="form-label">Select Input Method:</label>
        <div>
          <input type="radio" id="inputTypeText" name="input_type" value="text" checked onchange="toggleInputFields()">
          <label for="inputTypeText">Type/Paste Text</label>
        </div>
         <div>
          <input type="radio" id="inputTypeFile" name="input_type" value="file" onchange="toggleInputFields()">
          <label for="inputTypeFile">Upload File</label>
        </div>
      </div>

      <div class="mb-3" id="textInputDiv">
        <label for="textInput" class="form-label">Enter Text (UTF-8):</label>
        <textarea id="textInput" name="text_input" rows="5" class="form-control"></textarea>
      </div>

      <div class="mb-3" id="fileInputDiv" style="display:none;">
        <label for="fileInput" class="form-label">Select File:</label>
        <input type="file" id="fileInput" name="file_input" class="form-control">
      </div>

      <button type="submit" class="btn btn-primary">Calculate Hashes</button>
    </form>

    {% if md5_hash or sha256_hash %}
    <hr>
    <h4>Hashing Results:</h4>
    {% if input_filename %}
    <p><strong>Input File:</strong> {{ input_filename }}</p>
    {% elif input_text_snippet %}
    <p><strong>Input Text Snippet:</strong> <code style="overflow-wrap: break-word;">{{ input_text_snippet }}...</code></p>
    {% endif %}

    <div class="mb-2">
        <label for="md5Result" class="form-label"><strong>MD5 Hash:</strong></label>
        <div class="input-group">
            <input type="text" id="md5Result" class="form-control" value="{{ md5_hash }}" readonly>
            <button class="btn btn-outline-secondary copy-btn" onclick="copyToClipboardInput('md5Result', this)">Copy</button>
        </div>
    </div>

    <div class="mb-2">
        <label for="sha256Result" class="form-label"><strong>SHA256 Hash:</strong></label>
        <div class="input-group">
            <input type="text" id="sha256Result" class="form-control" value="{{ sha256_hash }}" readonly>
            <button class="btn btn-outline-secondary copy-btn" onclick="copyToClipboardInput('sha256Result', this)">Copy</button>
        </div>
    </div>
    {% endif %}
    {% if error %}
    <p class="text-danger mt-3">{{ error }}</p>
    {% endif %}
  </div>
</div>

<script>
function toggleInputFields() {
  const textInputDiv = document.getElementById('textInputDiv');
  const fileInputDiv = document.getElementById('fileInputDiv');
  const textInput = document.getElementById('textInput');
  const fileInput = document.getElementById('fileInput');

  if (document.getElementById('inputTypeText').checked) {
    textInputDiv.style.display = 'block';
    fileInputDiv.style.display = 'none';
    textInput.required = true;
    fileInput.required = false;
  } else {
    textInputDiv.style.display = 'none';
    fileInputDiv.style.display = 'block';
    textInput.required = false;
    fileInput.required = true;
  }
}

function copyToClipboardInput(inputId, buttonElement) {
  const inputElement = document.getElementById(inputId);
  inputElement.select();
  inputElement.setSelectionRange(0, 99999); /* For mobile devices */
  navigator.clipboard.writeText(inputElement.value).then(function() {
    const originalText = buttonElement.innerHTML;
    buttonElement.textContent = 'Copied!';
    setTimeout(() => { buttonElement.innerHTML = originalText; }, 2000);
  }, function(err) {
    console.error('Async: Could not copy text: ', err);
    alert('Failed to copy text.');
  });
}

// Initialize fields on page load
document.addEventListener('DOMContentLoaded', toggleInputFields);
</script>
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
    'my_pgp.html': my_pgp_template,
    'hashing.html': hashing_template,
}

app.jinja_loader = DictLoader(template_dict)

@app.route('/encryption/', methods=['GET', 'POST'])
def index():
    title = "PGP Key Pair Generator"
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        comment = request.form.get('comment', '')
        passphrase = request.form.get('passphrase')
        try:
            uid = pgpy.PGPUID.new(name, comment=comment, email=email)
            key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
            key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                        hashes=[HashAlgorithm.SHA256],
                        ciphers=[SymmetricKeyAlgorithm.AES256],
                        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
            if passphrase:
                key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

            public_key_str = str(key.pubkey)
            private_key_str = str(key)
            filename = secure_filename(f"{name.replace(' ', '_')}_{email.split('@')[0]}")
            keys_store[filename] = {'public': public_key_str, 'private': private_key_str}
            return render_template('index.html', title=title, public_key=public_key_str, filename=filename)
        except Exception as e:
            return render_template('index.html', title=title, error=f"Error generating key: {e}")
    return render_template('index.html', title=title)

@app.route('/encryption/download_public')
def download_public():
    filename = request.args.get('name')
    if filename and filename in keys_store:
        return Response(keys_store[filename]['public'], mimetype='application/pgp-keys',
                        headers={"Content-Disposition": f"attachment;filename={filename}_public.asc"})
    return "Key not found", 404

@app.route('/encryption/download_private')
def download_private():
    filename = request.args.get('name')
    if filename and filename in keys_store:
        return Response(keys_store[filename]['private'], mimetype='application/pgp-keys',
                        headers={"Content-Disposition": f"attachment;filename={filename}_private.asc"})
    return "Key not found", 404

@app.route('/encryption/aes_encrypt', methods=['GET', 'POST'])
def aes_encrypt():
    title = "AES Encrypt File"
    if request.method == 'POST':
        if 'file' not in request.files or not request.files['file'].filename:
             return render_template('aes_encrypt.html', title=title, error="No file selected")
        file = request.files['file']
        password = request.form['password']
        if not password:
             return render_template('aes_encrypt.html', title=title, error="Password is required")

        try:
            data = file.read()
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(algorithm=crypto_hashes.SHA256(), length=32, salt=salt, iterations=390000, backend=default_backend())
            key = kdf.derive(password.encode())
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(data) + encryptor.finalize()
            encrypted_blob = salt + iv + encryptor.tag + encrypted_data
            fname_base = secure_filename(file.filename)
            fname = f"{uuid.uuid4().hex}_{fname_base}"
            aes_store[fname] = encrypted_blob
            return render_template('aes_encrypt.html', title=title, encrypted=True, filename=fname)
        except Exception as e:
            return render_template('aes_encrypt.html', title=title, error=f"Encryption failed: {type(e).__name__}")
    return render_template('aes_encrypt.html', title=title)

@app.route('/encryption/download_encrypted')
def download_encrypted():
    fname = request.args.get('fname')
    if fname and fname in aes_store:
        original_fname = "_".join(fname.split('_')[1:])
        if not original_fname:
             original_fname = "encrypted_file"
        return Response(aes_store[fname], mimetype='application/octet-stream',
                        headers={"Content-Disposition": f"attachment;filename={original_fname}.enc"})
    return "Encrypted file not found", 404

@app.route('/encryption/aes_decrypt', methods=['GET', 'POST'])
def aes_decrypt():
    title = "AES Decrypt File"
    if request.method == 'POST':
        if 'file' not in request.files or not request.files['file'].filename:
             return render_template('aes_decrypt.html', title=title, error="No file selected")
        file = request.files['file']
        password = request.form['password']
        if not password:
            return render_template('aes_decrypt.html', title=title, error="Password is required")

        try:
            content = file.read()
            if len(content) < 44:
                raise ValueError("File is too short to be a valid encrypted file (missing salt/iv/tag/data).")
            salt = content[:16]
            iv = content[16:28]
            tag = content[28:44]
            enc_data = content[44:]

            kdf = PBKDF2HMAC(algorithm=crypto_hashes.SHA256(), length=32, salt=salt, iterations=390000, backend=default_backend())
            key = kdf.derive(password.encode())
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            dec_data = decryptor.update(enc_data) + decryptor.finalize()

            sf_name = secure_filename(file.filename)
            orig_filename = sf_name.replace(".enc", "") if sf_name.endswith(".enc") else f"decrypted_{sf_name}"
            if not orig_filename:
                   orig_filename="decrypted_file"

            return send_file(BytesIO(dec_data), as_attachment=True, download_name=orig_filename, mimetype="application/octet-stream")
        except ValueError as e:
             return render_template('aes_decrypt.html', title=title, error=f"Decryption failed: {str(e)}")
        except Exception as e:
            return render_template('aes_decrypt.html', title=title, error=f"Decryption failed. Incorrect password, corrupted file, or invalid format. ({type(e).__name__})")
    return render_template('aes_decrypt.html', title=title)

@app.route('/encryption/pgp_encrypt', methods=['GET', 'POST'])
def pgp_encrypt():
    title="PGP Encrypt Message For Recipient"
    if request.method == 'POST':
        recipient_key_blob = request.form['recipient_key']
        message_text = request.form['message']
        error_msg = None
        encrypted_message_str = None
        filename = None
        try:
            recipient_pub_key, _ = pgpy.PGPKey.from_blob(recipient_key_blob)
            if not recipient_pub_key.is_public:
                 raise ValueError("Provided key is not a public key.")
            msg = pgpy.PGPMessage.new(message_text, sensitive=True)

            encrypted = recipient_pub_key.encrypt(msg, cipher=SymmetricKeyAlgorithm.AES256)
            encrypted_message_str = str(encrypted)
            filename = uuid.uuid4().hex
            pgp_store[filename] = encrypted_message_str
        except ValueError as e:
             error_msg = f"Invalid PGP Key: {str(e)}"
        except Exception as e:
            error_msg = f"Encryption Error: {str(e)}"

        return render_template('pgp_encrypt.html', title=title,
                               encrypted_message=encrypted_message_str,
                               filename=filename, error=error_msg)
    return render_template('pgp_encrypt.html', title=title)

@app.route('/encryption/download_pgp')
def download_pgp():
    fname = request.args.get('fname')
    if fname and fname in pgp_store:
        return Response(pgp_store[fname], mimetype='application/pgp-encrypted',
                        headers={"Content-Disposition": f"attachment;filename={fname}_encrypted.asc"})
    return "Encrypted message not found", 404

@app.route('/encryption/pgp_demo', methods=['GET', 'POST'])
def pgp_demo():
    title="PGP Encrypt/Decrypt Demo"
    if request.method == 'POST':
        demo_message = request.form['demo_message']
        try:
            key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
            uid = pgpy.PGPUID.new("Demo User", comment="Temporary Key", email="demo@example.com")
            key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications},
                        hashes=[HashAlgorithm.SHA256],
                        ciphers=[SymmetricKeyAlgorithm.AES256],
                        compression=[CompressionAlgorithm.Uncompressed])

            public_key_str = str(key.pubkey)
            private_key_str = str(key)

            msg = pgpy.PGPMessage.new(demo_message)
            encrypted_msg = key.pubkey.encrypt(msg)
            decrypted_msg = key.decrypt(encrypted_msg).message

            return render_template('pgp_demo.html', title=title, public_key=public_key_str, private_key=private_key_str,
                                   original_message=demo_message, encrypted_message=str(encrypted_msg), decrypted_message=decrypted_msg)
        except Exception as e:
            return render_template('pgp_demo.html', title=title, error=f"Demo failed: {e}")
    return render_template('pgp_demo.html', title=title)

@app.route('/encryption/raw_rsa', methods=['GET', 'POST'])
def raw_rsa():
    title = "Generate RSA SSH Key Pair"
    if request.method == 'POST':
        try:
            key_size = int(request.form.get('key_size', 4096))
            if key_size not in [2048, 3072, 4096]:
                key_size = 4096

            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
            public_key = private_key.public_key()

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8, # Use PKCS8 (newer, more common)
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            public_openssh = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ).decode('utf-8')

            rid = uuid.uuid4().hex
            raw_rsa_store[rid] = {"private": private_pem, "public": public_openssh, "key_size": key_size}
            return render_template('raw_rsa.html', title=title, private_key=private_pem, public_key=public_openssh, rid=rid, key_size=key_size)
        except Exception as e:
             return render_template('raw_rsa.html', title=title, error=f"Key generation failed: {e}")

    return render_template('raw_rsa.html', title=title)

@app.route('/encryption/download_raw_private')
def download_raw_private():
    rid = request.args.get('rid')
    if rid and rid in raw_rsa_store:
        key_size = raw_rsa_store[rid]['key_size']
        filename = f"id_rsa_{key_size}_{rid[:8]}"
        return Response(raw_rsa_store[rid]['private'], mimetype='application/octet-stream',
                        headers={"Content-Disposition": f"attachment;filename={filename}"})
    return "Key not found", 404

@app.route('/encryption/download_raw_public')
def download_raw_public():
    rid = request.args.get('rid')
    if rid and rid in raw_rsa_store:
        key_size = raw_rsa_store[rid]['key_size']
        filename = f"id_rsa_{key_size}_{rid[:8]}.pub"
        return Response(raw_rsa_store[rid]['public'], mimetype='text/plain',
                        headers={"Content-Disposition": f"attachment;filename={filename}"})
    return "Key not found", 404

@app.route('/encryption/rsa_hand', methods=['GET', 'POST'])
def rsa_hand():
    title = "Interactive RSA Demo"
    def is_probable_prime(n, k=10):
        if n < 2: return False
        if n == 2 or n == 3: return True
        if n % 2 == 0 or n % 3 == 0: return False
        d = 5
        while d * d <= n:
            if n % d == 0 or n % (d + 2) == 0:
                return False
            d += 6
        return True

    def generate_prime(bits):
        max_attempts = 100 * bits
        attempts = 0
        while attempts < max_attempts:
            p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
            if is_probable_prime(p, k=5):
                return p
            attempts += 1
        return None

    def gcd(a, b):
        while b:
            a, b = b, a % b
        return a

    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        d, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return d, x, y

    def modinv(a, m):
        d, x, y = extended_gcd(a, m)
        if d != 1:
            return None
        return x % m

    if request.method == 'POST':
        prime_source = request.form.get('prime_source', 'manual')
        message = request.form.get('message') or "Default message"
        p, q, error = None, None, None

        if prime_source == 'manual':
            try:
                p_in = int(request.form['p'])
                q_in = int(request.form['q'])
                if p_in == q_in: error = "p and q must be different primes."
                elif not is_probable_prime(p_in): error = f"{p_in} is not prime."
                elif not is_probable_prime(q_in): error = f"{q_in} is not prime."
                else: p, q = p_in, q_in
            except (ValueError, KeyError): error = "Invalid integer input for manual primes p and q."
            except Exception as e: error = f"Input Error: {e}"
        else:
            try:
                bits = int(request.form.get('bits', 12))
                if not (8 <= bits <= 32): error = "Bit length must be between 8 and 32 for this demo."
                else:
                    p = generate_prime(bits)
                    q = generate_prime(bits)
                    tries = 0
                    max_tries = 10
                    while (p is None or q is None or p == q) and tries < max_tries:
                        if p is None: p = generate_prime(bits)
                        if q is None or p == q: q = generate_prime(bits)
                        tries += 1
                    if p is None or q is None or p == q: error = f"Failed to generate distinct primes of {bits} bits after {max_tries} attempts."
            except (ValueError, KeyError): error = "Invalid integer input for bit length."
            except Exception as e: error = f"Generation Error: {e}"

        if error: return render_template('rsa_hand.html', title=title, error=error)
        if p is None or q is None: return render_template('rsa_hand.html', title=title, error="Failed to get valid primes p and q.")

        try:
            n = p * q
            phi = (p - 1) * (q - 1)
            e = 65537
            if e >= phi or gcd(e, phi) != 1:
                e = 3
                max_e_tries = 1000
                current_e_try = 0
                while gcd(e, phi) != 1 and current_e_try < max_e_tries:
                    e += 2
                    if e >= phi: break
                    current_e_try +=1
                if e>= phi or gcd(e, phi) != 1:
                    return render_template('rsa_hand.html', title=title, error=f"Could not find suitable public exponent e for phi={phi}.")

            d = modinv(e, phi)
            if d is None: return render_template('rsa_hand.html', title=title, error=f"Could not compute modular inverse d for e={e}, phi={phi}.")

            message_bytes = message.encode('utf-8')
            orig_numbers = [int(b) for b in message_bytes]

            if n < 256: return render_template('rsa_hand.html', title=title, error=f"Modulus n={n} is too small (must be >= 256 for standard ASCII). Choose larger primes.")

            encrypted_numbers = [pow(m, e, n) for m in orig_numbers]
            decrypted_numbers = [pow(c, d, n) for c in encrypted_numbers]
            decrypted_bytes = bytes(decrypted_numbers)
            decrypted_message = decrypted_bytes.decode('utf-8', errors='replace')

        except OverflowError:
             return render_template('rsa_hand.html', title=title, error="Calculation resulted in a number too large to handle. Try smaller primes or shorter message.")
        except Exception as ex:
            return render_template('rsa_hand.html', title=title, error=f"Error during calculation: {str(ex)}")

        return render_template('rsa_hand.html', title=title, p=p, q=q, n=n, phi=phi, e=e, d=d,
                               orig_numbers=orig_numbers, encrypted_numbers=encrypted_numbers,
                               decrypted_numbers=decrypted_numbers, message=message, decrypted_message=decrypted_message)
    return render_template('rsa_hand.html', title=title)


@app.route('/encryption/ecc_hand', methods=['GET', 'POST'])
def ecc_hand():
    title = "Generate ECDSA SSH Key Pair"
    if request.method == 'POST':
        curve_name = request.form.get('curve')
        curve, ssh_curve_name, error_msg = None, None, None

        try:
            if curve_name == "SECP256R1": curve, ssh_curve_name = ec.SECP256R1(), "nistp256"
            elif curve_name == "SECP384R1": curve, ssh_curve_name = ec.SECP384R1(), "nistp384"
            elif curve_name == "SECP521R1": curve, ssh_curve_name = ec.SECP521R1(), "nistp521"
            else: error_msg = "Invalid curve selected"
        except Exception as ex: error_msg = f"Error loading curve {curve_name}: {str(ex)}"

        if error_msg: return render_template('ecc_hand.html', title=title, error=error_msg)
        if not curve: return render_template('ecc_hand.html', title=title, error="Curve object could not be created.")

        try:
            private_key = ec.generate_private_key(curve, default_backend())
            public_key = private_key.public_key()

            private_openssh = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            public_openssh = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ).decode('utf-8')

            ecc_id = uuid.uuid4().hex
            ecc_store[ecc_id] = {
                "private": private_openssh,
                "public": public_openssh,
                "curve": curve_name,
                "ssh_curve_name": ssh_curve_name
            }

            return render_template('ecc_hand.html', title=title, curve=curve_name,
                                   private_key_openssh=private_openssh,
                                   public_key_openssh=public_openssh,
                                   ecc_id=ecc_id, ssh_curve_name=ssh_curve_name)

        except Exception as ex:
            return render_template('ecc_hand.html', title=title, error="Error during key generation: " + str(ex))

    return render_template('ecc_hand.html', title=title)

@app.route('/encryption/download_ecc_private')
def download_ecc_private():
    eid = request.args.get('eid')
    if eid and eid in ecc_store:
        ssh_curve_name = ecc_store[eid].get('ssh_curve_name', 'ecdsa')
        filename = f"id_ecdsa_{ssh_curve_name}_{eid[:8]}"
        return Response(ecc_store[eid]['private'], mimetype='application/octet-stream',
                        headers={"Content-Disposition": f"attachment;filename={filename}"})
    return "Key not found", 404

@app.route('/encryption/download_ecc_public')
def download_ecc_public():
    eid = request.args.get('eid')
    if eid and eid in ecc_store:
        ssh_curve_name = ecc_store[eid].get('ssh_curve_name', 'ecdsa')
        filename = f"id_ecdsa_{ssh_curve_name}_{eid[:8]}.pub"
        return Response(ecc_store[eid]['public'], mimetype='text/plain',
                        headers={"Content-Disposition": f"attachment;filename={filename}"})
    return "Key not found", 404

@app.route('/encryption/ed25519_hand', methods=['GET', 'POST'])
def ed25519_hand():
    title = "Generate Ed25519 SSH Key Pair"
    if request.method == 'POST':
        try:
            private_key = ed25519.Ed25519PrivateKey.generate()
            public_key = private_key.public_key()

            private_key_openssh = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            public_key_openssh = public_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ).decode('utf-8')

            ed_id = uuid.uuid4().hex
            ed25519_store[ed_id] = {
                "private": private_key_openssh,
                "public": public_key_openssh
            }

            return render_template('ed25519_hand.html', title=title, ed_id=ed_id,
                                   private_key_openssh=private_key_openssh,
                                   public_key_openssh=public_key_openssh)

        except Exception as ex:
            return render_template('ed25519_hand.html', title=title, error="Error generating Ed25519 key: " + str(ex))

    return render_template('ed25519_hand.html', title=title)

@app.route('/encryption/download_ed25519_private')
def download_ed25519_private():
    eid = request.args.get('eid')
    if eid and eid in ed25519_store:
        filename = f"id_ed25519_{eid[:8]}"
        return Response(ed25519_store[eid]['private'], mimetype='application/octet-stream',
                        headers={"Content-Disposition": f"attachment;filename={filename}"})
    return "Key not found", 404

@app.route('/encryption/download_ed25519_public')
def download_ed25519_public():
    eid = request.args.get('eid')
    if eid and eid in ed25519_store:
         filename = f"id_ed25519_{eid[:8]}.pub"
         return Response(ed25519_store[eid]['public'], mimetype='text/plain',
                         headers={"Content-Disposition": f"attachment;filename={filename}"})
    return "Key not found", 404

@app.route('/encryption/x25519_hand', methods=['GET', 'POST'])
def x25519_hand():
    title = "X25519 Key Exchange Demo"
    if request.method == 'POST':
        try:
            a_private = x25519.X25519PrivateKey.generate()
            a_public = a_private.public_key()
            b_private = x25519.X25519PrivateKey.generate()
            b_public = b_private.public_key()

            shared_secret_a_bytes = a_private.exchange(b_public)
            shared_secret_b_bytes = b_private.exchange(a_public)

            shared_secret_a_hex = shared_secret_a_bytes.hex()
            shared_secret_b_hex = shared_secret_b_bytes.hex()

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

            return render_template('x25519_hand.html', title=title,
                                  shared_secret_a=shared_secret_a_hex, shared_secret_b=shared_secret_b_hex,
                                  a_private=a_private_pem, a_public=a_public_pem,
                                  b_private=b_private_pem, b_public=b_public_pem)
        except Exception as ex:
             return render_template('x25519_hand.html', title=title, error=f"Error during X25519 generation: {str(ex)}")

    return render_template('x25519_hand.html', title=title)

@app.route('/encryption/my_pgp', methods=['GET', 'POST'])
def my_pgp():
    title = "My PGP Information"
    encrypted_for_me = None
    encrypt_error = None
    verification_result = None
    verified_message_content = None
    verify_error = None

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'encrypt':
            message_to_encrypt = request.form.get('message_to_encrypt')
            if message_to_encrypt and MY_PUBLIC_PGP_KEY_OBJ:
                try:
                    msg = pgpy.PGPMessage.new(message_to_encrypt, sensitive=True, file=False)
                    encrypted = MY_PUBLIC_PGP_KEY_OBJ.encrypt(msg, cipher=SymmetricKeyAlgorithm.AES256)
                    encrypted_for_me = str(encrypted)
                except Exception as e:
                    encrypt_error = f"PGP encryption failed: {str(e)}"
            elif not MY_PUBLIC_PGP_KEY_OBJ:
                encrypt_error = "My public key could not be loaded."
            elif not message_to_encrypt:
                 encrypt_error = "No message provided to encrypt."

        elif action == 'verify':
            signed_message_blob = request.form.get('signed_message')
            if signed_message_blob and MY_PUBLIC_PGP_KEY_OBJ:
                try:
                    message = pgpy.PGPMessage.from_blob(signed_message_blob)
                    verification_result = MY_PUBLIC_PGP_KEY_OBJ.verify(message)
                    if verification_result:
                        # Attempt to get message content if signature is valid
                        if not message.is_encrypted:
                             # Check if it's just a signature or signed data
                            if message.issigned:
                                if hasattr(message, 'message') and message.message:
                                     verified_message_content = message.message
                                else:
                                     # If it's just a signature packet over nothing specific, report that.
                                     # This case might need more nuanced handling depending on expected input.
                                     verified_message_content = "[Signature verified, but no specific message content embedded]"
                            else:
                                verified_message_content = "[Message is not signed]"
                        else:
                            verified_message_content = "[Cannot display content of encrypted message]"
                except ValueError as e:
                     verify_error = f"Invalid PGP message format or signature: {str(e)}"
                     verification_result = False
                except Exception as e:
                    verify_error = f"PGP verification failed: {str(e)}"
                    verification_result = False
            elif not MY_PUBLIC_PGP_KEY_OBJ:
                verify_error = "My public key could not be loaded."
            elif not signed_message_blob:
                verify_error = "No signed message provided to verify."

    return render_template('my_pgp.html', title=title,
                           my_public_key=MY_PGP_PUBLIC_KEY,
                           encrypted_for_me=encrypted_for_me,
                           encrypt_error=encrypt_error,
                           verification_result=verification_result,
                           verified_message_content=verified_message_content,
                           verify_error=verify_error)

@app.route('/encryption/hashing', methods=['GET', 'POST'])
def hashing():
    title="Calculate Hashes"
    md5_hash = None
    sha256_hash = None
    input_filename = None
    input_text_snippet = None
    error = None

    if request.method == 'POST':
        input_type = request.form.get('input_type')
        hasher_md5 = hashlib.md5()
        hasher_sha256 = hashlib.sha256()

        try:
            if input_type == 'text':
                text_input = request.form.get('text_input')
                if text_input is not None:
                    data = text_input.encode('utf-8')
                    hasher_md5.update(data)
                    hasher_sha256.update(data)
                    md5_hash = hasher_md5.hexdigest()
                    sha256_hash = hasher_sha256.hexdigest()
                    input_text_snippet = text_input[:100] # Show a snippet
                else:
                    error = "No text was entered."
            elif input_type == 'file':
                if 'file_input' not in request.files or not request.files['file_input'].filename:
                    error = "No file selected."
                else:
                    file = request.files['file_input']
                    input_filename = secure_filename(file.filename)
                    chunk_size = 4096
                    while True:
                        chunk = file.read(chunk_size)
                        if not chunk:
                            break
                        hasher_md5.update(chunk)
                        hasher_sha256.update(chunk)
                    md5_hash = hasher_md5.hexdigest()
                    sha256_hash = hasher_sha256.hexdigest()
            else:
                error = "Invalid input type selected."

        except Exception as e:
            error = f"An error occurred during hashing: {str(e)}"

    return render_template('hashing.html', title=title,
                           md5_hash=md5_hash, sha256_hash=sha256_hash,
                           input_filename=input_filename, input_text_snippet=input_text_snippet,
                           error=error)


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)