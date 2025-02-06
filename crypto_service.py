from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers import algorithms as decrepit_algorithms  # For TripleDES
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import logging

class CryptoService:
    def __init__(self):
        self.rsa_private_keys = {}  # Session-based in-memory storage
    
    # AES-256-CBC Implementation
    def aes_encrypt(self, plaintext, password, salt=None):
        try:
            salt = salt or os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()
            
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            return {
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'iv': base64.b64encode(iv).decode(),
                'salt': base64.b64encode(salt).decode()
            }
        except Exception as e:
            logging.error(f"AES Encryption Error: {str(e)}")
            raise ValueError("Encryption failed - invalid inputs or algorithm error")

    def aes_decrypt(self, ciphertext, password, iv, salt):
        try:
            key = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=base64.b64decode(salt),
                iterations=100000,
                backend=default_backend()
            ).derive(password.encode())
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(base64.b64decode(iv)), 
                          backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode()
        except (ValueError, TypeError) as e:
            logging.error(f"AES Decryption Error: {str(e)}")
            raise ValueError("Decryption failed - invalid key or corrupted data")

    # Triple DES Implementation
    def triple_des_encrypt(self, plaintext, password):
        try:
            # Derive 24-byte key from password using PBKDF2
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=24,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            # Handle both string and byte inputs
            if isinstance(password, str):
                password_bytes = password.encode('utf-8')
            else:
                password_bytes = password
            key = kdf.derive(password_bytes)
                
            padder = padding.PKCS7(64).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()
            
            iv = os.urandom(8)
            cipher = Cipher(decrepit_algorithms.TripleDES(key), modes.CBC(iv),
                          backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            return {
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'iv': base64.b64encode(iv).decode(),
                'salt': base64.b64encode(salt).decode()
            }
        except Exception as e:
            logging.error(f"Triple DES Encryption Error: {str(e)}", exc_info=True)
            raise ValueError("Triple DES encryption failed") from e

    def triple_des_decrypt(self, ciphertext, password, iv, salt):
        try:
            # Convert inputs to bytes
            # Handle password conversion
            if isinstance(password, str):
                password_bytes = password.encode('utf-8')
            else:
                password_bytes = password
            iv = base64.b64decode(iv)
            ciphertext = base64.b64decode(ciphertext)
            salt = base64.b64decode(salt)

            # Derive key from password using stored salt
            if isinstance(password, str):
                password_bytes = password.encode('utf-8')
            else:
                password_bytes = password
                
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=24,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password_bytes)
                
            cipher = Cipher(decrepit_algorithms.TripleDES(key), modes.CBC(iv),
                          backend=default_backend())
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = padding.PKCS7(64).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            
            return plaintext.decode()
        except Exception as e:
            logging.error(f"Triple DES Decryption Error: {str(e)}", exc_info=True)
            raise ValueError("Triple DES decryption failed") from e

    # RSA-2048 Implementation
    def generate_rsa_keypair(self, session_id):
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            self.rsa_private_keys[session_id] = private_key
            return private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        except Exception as e:
            logging.error(f"RSA Keygen Error: {str(e)}")
            raise ValueError("Key generation failed")

    def rsa_encrypt(self, plaintext, public_key):
        try:
            public_key = serialization.load_pem_public_key(
                public_key,
                backend=default_backend()
            )
            ciphertext = public_key.encrypt(
                plaintext.encode(),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(ciphertext).decode()
        except Exception as e:
            logging.error(f"RSA Encryption Error: {str(e)}")
            raise ValueError("RSA encryption failed")

    def rsa_decrypt(self, ciphertext, session_id):
        if session_id not in self.rsa_private_keys:
            raise ValueError("Invalid session or expired private key")
            
        try:
            private_key = self.rsa_private_keys[session_id]
            plaintext = private_key.decrypt(
                base64.b64decode(ciphertext),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext.decode()
        except Exception as e:
            logging.error(f"RSA Decryption Error: {str(e)}")
            raise ValueError("RSA decryption failed")