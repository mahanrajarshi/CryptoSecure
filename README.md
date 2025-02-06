# CryptoSecure - Multi-Algorithm Encryption Suite

A Python-based cybersecurity project providing secure text encryption using AES, DES, and RSA algorithms.

## Features

- Three encryption modes:
  - AES-256 (Advanced Encryption Standard)
  - DES (Data Encryption Standard) 
  - RSA (Rivest-Shamir-Adleman) public/private key encryption
- Web interface for easy interaction
- API endpoints for programmatic access
- Comprehensive test coverage
- Configuration for production deployment (Nginx + Gunicorn)

## Requirements

- Python 3.8+
- OpenSSL libraries
- Cryptographic dependencies (listed in requirements.txt)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Command Line Interface
```python
from crypto_service import CryptoManager

# AES Encryption
encrypted_aes = CryptoManager.aes_encrypt("sensitive data", "strong_password")

# RSA Key Generation
private_key, public_key = CryptoManager.generate_rsa_keys()
```

### Web Interface
Start the Flask development server:
```bash
python app.py
```

Access the web interface at `http://localhost:5000`

### Testing
Run the test suite:
```bash
python -m pytest test_crypto.py
```

## Configuration

1. Production deployment:
```bash
gunicorn -c gunicorn.conf.py app:app
```

2. Nginx configuration template provided in `nginx.conf`

## Security Considerations

- Always store encryption keys securely
- Rotate keys regularly
- Use HTTPS in production environments
- Follow principle of least privilege for file permissions

## License
MIT License - See [LICENSE](LICENSE) for details

## Contributing
Pull requests welcome. Please ensure all tests pass and include new test cases.