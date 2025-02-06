from flask import Flask, request, jsonify, session, render_template
from crypto_service import CryptoService
from flask_wtf.csrf import CSRFProtect
import logging
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

csrf = CSRFProtect(app)
crypto = CryptoService()

@app.after_request
def add_security_headers(response):
    headers = {
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    }
    for header, value in headers.items():
        response.headers[header] = value
    return response

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()
        algorithm = data['algorithm']
        plaintext = data['plaintext']
        password = data.get('password', '')
        if 'sid' not in session:
            session['sid'] = secrets.token_hex(16)
        session_id = session['sid']

        if algorithm == 'aes-256-cbc':
            result = crypto.aes_encrypt(plaintext, password)
        elif algorithm == 'tripledes':
            result = crypto.triple_des_encrypt(plaintext, password.encode())
        elif algorithm == 'rsa-2048':
            public_key = crypto.generate_rsa_keypair(session_id)
            result = {'public_key': public_key.decode(), 'ciphertext': crypto.rsa_encrypt(plaintext, public_key)}
        else:
            return jsonify({'error': 'Invalid algorithm'}), 400

        return jsonify(result)
    except Exception as e:
        logging.error(f"Encryption error: {str(e)}")
        return jsonify({'error': 'Encryption failed'}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        algorithm = data['algorithm']
        ciphertext = data['ciphertext']
        password = data.get('password', '')
        iv = data.get('iv', '')
        salt = data.get('salt', '')
        session_id = session.get('sid', '')
        if not session_id:
            return jsonify({'error': 'No active session'}), 401

        if algorithm == 'aes-256-cbc':
            plaintext = crypto.aes_decrypt(ciphertext, password, iv, salt)
        elif algorithm == 'tripledes':
            plaintext = crypto.triple_des_decrypt(ciphertext, password.encode(), iv, data.get('salt', ''))
        elif algorithm == 'rsa-2048':
            plaintext = crypto.rsa_decrypt(ciphertext, session_id)
        else:
            return jsonify({'error': 'Invalid algorithm'}), 400

        return jsonify({'plaintext': plaintext})
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        return jsonify({'error': 'Decryption failed'}), 500

if __name__ == '__main__':
    app.run(ssl_context='adhoc', host='0.0.0.0', port=5000)
