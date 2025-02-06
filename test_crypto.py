import pytest
from crypto_service import CryptoService
import base64
import os

@pytest.fixture
def crypto():
    return CryptoService()

def test_aes_encrypt_decrypt(crypto):
    # Test valid AES operation
    plaintext = "Secret message 123"
    password = "strong-password"
    
    encrypted = crypto.aes_encrypt(plaintext, password)
    assert 'ciphertext' in encrypted
    assert 'iv' in encrypted
    assert 'salt' in encrypted
    
    decrypted = crypto.aes_decrypt(
        encrypted['ciphertext'],
        password,
        encrypted['iv'],
        encrypted['salt']
    )
    assert decrypted == plaintext

def test_aes_invalid_decryption(crypto):
    # Test decryption with wrong password
    encrypted = crypto.aes_encrypt("test", "password")
    with pytest.raises(ValueError):
        crypto.aes_decrypt(encrypted['ciphertext'], "wrong-password", encrypted['iv'], encrypted['salt'])

def test_triple_des_valid(crypto):
    # Test valid Triple DES operation
    plaintext = "Triple DES test"
    key = os.urandom(24)  # Generate proper 24-byte key
    
    encrypted = crypto.triple_des_encrypt(plaintext, key)
    assert 'ciphertext' in encrypted
    assert 'iv' in encrypted
    
    # Test decryption
    decrypted = crypto.triple_des_decrypt(
        encrypted['ciphertext'],
        key,
        encrypted['iv'],
        encrypted['salt']
    )
    assert decrypted == plaintext

def test_triple_des_invalid_key(crypto):
    # Test invalid key length
    with pytest.raises(ValueError):
        # Pass both invalid key and non-byte key to test validation
        crypto.triple_des_encrypt("test", 12345)  # Test non-bytes/string input

def test_triple_des_decrypt(crypto):
    # Test full encryption/decryption cycle
    plaintext = "Important secret message"
    key = os.urandom(24)
    
    encrypted = crypto.triple_des_encrypt(plaintext, key)
    decrypted = crypto.triple_des_decrypt(
        encrypted['ciphertext'],
        key,
        encrypted['iv'],
        encrypted['salt']
    )
    assert decrypted == plaintext

def test_rsa_flow(crypto):
    # Test full RSA workflow
    session_id = "test-session"
    plaintext = "RSA encrypted message"
    
    public_key = crypto.generate_rsa_keypair(session_id)
    ciphertext = crypto.rsa_encrypt(plaintext, public_key)
    decrypted = crypto.rsa_decrypt(ciphertext, session_id)
    
    assert decrypted == plaintext

def test_rsa_invalid_session(crypto):
    # Test decryption with invalid session
    with pytest.raises(ValueError):
        crypto.rsa_decrypt("invalid-ciphertext", "non-existent-session")