import os
import secrets
import string
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from Crypto.Cipher import DES3, AES
from Crypto.Util.Padding import pad, unpad
from cryptography.exceptions import InvalidSignature
import base64
import json

# Encryption methods
ENCRYPTION_METHODS = {
    'aes-128-cbc': 'AES-128 (CBC Mode)',
    'aes-256-cbc': 'AES-256 (CBC Mode)',
    'aes-128-ctr': 'AES-128 (CTR Mode)',
    'aes-256-ctr': 'AES-256 (CTR Mode)',
    '3des-cbc': '3DES (CBC Mode)',
    'rsa': 'RSA Public/Private Key'
}

# Hash methods
HASH_METHODS = {
    'sha256': 'SHA-256',
    'sha384': 'SHA-384',
    'sha512': 'SHA-512',
    'sha3-256': 'SHA3-256',
    'sha3-512': 'SHA3-512'
}

# Generate secure password
def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

# Derive key from password
def derive_key_from_password(password, salt=None, key_size=32):
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_size,
        salt=salt,
        iterations=100000,
    )
    
    key = kdf.derive(password.encode())
    return key, salt

# AES encryption
def encrypt_aes(data, key, mode='cbc', key_size=256, iv=None):
    if isinstance(data, str):
        data = data.encode()
    
    # Ensure key is the right size
    if len(key) * 8 != key_size:
        raise ValueError(f"Key must be {key_size // 8} bytes for AES-{key_size}")
    
    # Generate or use provided IV
    if iv is None:
        iv = os.urandom(16)  # AES block size
    
    if mode.lower() == 'cbc':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
    elif mode.lower() == 'ctr':
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
        ciphertext = cipher.encrypt(data)
    else:
        raise ValueError("Mode must be 'cbc' or 'ctr'")
    
    # Return IV and ciphertext
    return {
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'mode': mode,
        'key_size': key_size
    }

# AES decryption
def decrypt_aes(encrypted_data, key):
    try:
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        mode = encrypted_data.get('mode', 'cbc').lower()
        
        print(f"AES decryption params: IV length={len(iv)}, ciphertext length={len(ciphertext)}, mode={mode}")
        
        if mode == 'cbc':
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            try:
                plaintext = unpad(padded_plaintext, AES.block_size)
            except Exception as e:
                raise ValueError(f"Padding error: {str(e)}. This could indicate an incorrect key or corrupted data.")
        elif mode == 'ctr':
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
            plaintext = cipher.decrypt(ciphertext)
        else:
            raise ValueError(f"Unsupported AES mode: {mode}")
        
        return plaintext
    except KeyError as e:
        raise ValueError(f"Missing required parameter: {str(e)}")
    except ValueError as e:
        raise ValueError(f"AES decryption error: {str(e)}")
    except Exception as e:
        raise ValueError(f"Unexpected error during AES decryption: {str(e)}")

# 3DES encryption
def encrypt_3des(data, key, mode='cbc', iv=None):
    if isinstance(data, str):
        data = data.encode()
    
    # 3DES requires 24-byte key (192 bits)
    if len(key) != 24:
        raise ValueError("Key must be 24 bytes for 3DES")
    
    # Generate or use provided IV
    if iv is None:
        iv = os.urandom(8)  # 3DES block size
    
    if mode.lower() == 'cbc':
        cipher = DES3.new(key, DES3.MODE_CBC, iv)
        padded_data = pad(data, DES3.block_size)
        ciphertext = cipher.encrypt(padded_data)
    else:
        raise ValueError("Only CBC mode is supported for 3DES")
    
    # Return IV and ciphertext
    return {
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'mode': mode
    }

# 3DES decryption
def decrypt_3des(encrypted_data, key):
    try:
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        mode = encrypted_data.get('mode', 'cbc').lower()
        
        print(f"3DES decryption params: IV length={len(iv)}, ciphertext length={len(ciphertext)}, mode={mode}")
        
        if mode == 'cbc':
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            try:
                plaintext = unpad(padded_plaintext, DES3.block_size)
            except Exception as e:
                raise ValueError(f"Padding error: {str(e)}. This could indicate an incorrect key or corrupted data.")
        else:
            raise ValueError(f"Unsupported 3DES mode: {mode}")
        
        return plaintext
    except KeyError as e:
        raise ValueError(f"Missing required parameter: {str(e)}")
    except ValueError as e:
        raise ValueError(f"3DES decryption error: {str(e)}")
    except Exception as e:
        raise ValueError(f"Unexpected error during 3DES decryption: {str(e)}")

# RSA key generation
def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    
    # Export keys in PEM format
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    return {
        'private_key': private_pem.decode('utf-8'),
        'public_key': public_pem.decode('utf-8')
    }

# RSA encryption
def encrypt_rsa(data, public_key_pem):
    if isinstance(data, str):
        data = data.encode()
    
    public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
    
    # RSA can only encrypt small amounts of data, so we use it to encrypt a symmetric key
    # and then use that symmetric key with AES to encrypt the actual data
    symmetric_key = os.urandom(32)  # 256-bit key for AES
    
    # Encrypt the symmetric key with RSA
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Encrypt the data with AES using the symmetric key
    aes_encrypted = encrypt_aes(data, symmetric_key, mode='cbc', key_size=256)
    
    # Combine the encrypted symmetric key and the AES encryption details
    result = {
        'encrypted_symmetric_key': base64.b64encode(encrypted_symmetric_key).decode('utf-8'),
        'iv': aes_encrypted['iv'],
        'ciphertext': aes_encrypted['ciphertext'],
        'mode': aes_encrypted['mode'],
        'encryption_method': 'rsa+aes'
    }
    
    return result

# RSA decryption
def decrypt_rsa(encrypted_data, private_key_pem):
    encrypted_symmetric_key = base64.b64decode(encrypted_data['encrypted_symmetric_key'])
    
    # Load the private key
    private_key = load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )
    
    # Decrypt the symmetric key
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Prepare AES decryption data
    aes_encrypted = {
        'iv': encrypted_data['iv'],
        'ciphertext': encrypted_data['ciphertext'],
        'mode': encrypted_data['mode'],
        'key_size': 256
    }
    
    # Decrypt the ciphertext with AES using the symmetric key
    plaintext = decrypt_aes(aes_encrypted, symmetric_key)
    
    return plaintext

# Diffie-Hellman key exchange
def generate_dh_parameters():
    # Generate parameters for Diffie-Hellman
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    
    # Serialize parameters
    params_pem = parameters.parameter_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    return params_pem.decode('utf-8')

def generate_dh_keypair(params_pem):
    # Load parameters
    parameters = dh.DHParameterNumbers.from_data(
        load_pem_public_key(params_pem.encode('utf-8'))
    ).parameters
    
    # Generate private key
    private_key = parameters.generate_private_key()
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize keys
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    return {
        'private_key': private_pem.decode('utf-8'),
        'public_key': public_pem.decode('utf-8')
    }

def compute_dh_shared_key(private_key_pem, peer_public_key_pem):
    # Load keys
    private_key = load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )
    
    peer_public_key = load_pem_public_key(peer_public_key_pem.encode('utf-8'))
    
    # Compute shared key
    shared_key = private_key.exchange(peer_public_key)
    
    # Derive a usable symmetric key using HKDF
    derived_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'cryptosite',
        iterations=100000,
    ).derive(shared_key)
    
    return base64.b64encode(derived_key).decode('utf-8')

# File hashing functions
def hash_file(file_data, algorithm='sha256'):
    if algorithm == 'sha256':
        hash_obj = hashlib.sha256()
    elif algorithm == 'sha384':
        hash_obj = hashlib.sha384()
    elif algorithm == 'sha512':
        hash_obj = hashlib.sha512()
    elif algorithm == 'sha3-256':
        hash_obj = hashlib.sha3_256()
    elif algorithm == 'sha3-512':
        hash_obj = hashlib.sha3_512()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    hash_obj.update(file_data)
    return hash_obj.hexdigest()

# Compare two hash values
def compare_hashes(hash1, hash2):
    return secrets.compare_digest(hash1, hash2)

# Encrypt a file using selected method
def encrypt_file(file_data, method, key=None, iv=None, original_filename=None):
    # Store the original file extension if provided
    original_ext = None
    if original_filename:
        ext_parts = original_filename.rsplit('.', 1)
        if len(ext_parts) > 1:
            original_ext = ext_parts[1]
    
    if method.startswith('aes'):
        parts = method.split('-')
        key_size = int(parts[1])
        mode = parts[2]
        
        # If key is provided as a base64 string, decode it
        if key is not None and isinstance(key, str):
            try:
                key = base64.b64decode(key)
            except Exception as e:
                raise ValueError(f"Invalid key format: {str(e)}")
        
        # If no key provided, generate a new one
        if key is None:
            key = os.urandom(key_size // 8)
            
        # Verify key length
        expected_key_bytes = key_size // 8
        if len(key) != expected_key_bytes:
            raise ValueError(f"Key must be {expected_key_bytes} bytes for AES-{key_size}, got {len(key)} bytes")
            
        result = encrypt_aes(file_data, key, mode=mode, key_size=key_size, iv=iv)
        result['key'] = base64.b64encode(key).decode('utf-8')
        result['encryption_method'] = method
        
        # Store original extension if available
        if original_ext:
            result['original_ext'] = original_ext
        
    elif method == '3des-cbc':
        # If key is provided as a base64 string, decode it
        if key is not None and isinstance(key, str):
            try:
                key = base64.b64decode(key)
            except Exception as e:
                raise ValueError(f"Invalid key format: {str(e)}")
                
        # If no key provided, generate a new one
        if key is None:
            key = os.urandom(24)  # 3DES uses 24-byte key (192 bits)
            
        # Verify key length
        if len(key) != 24:
            raise ValueError(f"Key must be 24 bytes for 3DES, got {len(key)} bytes")
            
        result = encrypt_3des(file_data, key, mode='cbc', iv=iv)
        result['key'] = base64.b64encode(key).decode('utf-8')
        result['encryption_method'] = method
        
        # Store original extension if available
        if original_ext:
            result['original_ext'] = original_ext
        
    elif method == 'rsa':
        if key is None:
            # Generate a new RSA keypair
            keypair = generate_rsa_keypair()
            public_key = keypair['public_key']
            
            # Store private key for later use
            result = encrypt_rsa(file_data, public_key)
            result['private_key'] = keypair['private_key']
            result['public_key'] = keypair['public_key']
        else:
            # Use provided public key
            result = encrypt_rsa(file_data, key)
            
        result['encryption_method'] = 'rsa'
        
        # Store original extension if available
        if original_ext:
            result['original_ext'] = original_ext
    else:
        raise ValueError(f"Unsupported encryption method: {method}")
    
    # Convert to JSON for storage
    return json.dumps(result)

# Decrypt a file using stored metadata and key
def decrypt_file(encrypted_data_json, key=None):
    # Parse the JSON data
    try:
        encrypted_data = json.loads(encrypted_data_json)
    except json.JSONDecodeError:
        raise ValueError("Invalid encrypted data format: not valid JSON")
    
    # Check for required fields
    if 'encryption_method' not in encrypted_data:
        raise ValueError("Invalid encrypted data: missing encryption method")
    if 'ciphertext' not in encrypted_data:
        raise ValueError("Invalid encrypted data: missing ciphertext")
        
    method = encrypted_data.get('encryption_method')
    print(f"Decrypting file with method: {method}")
    
    if method.startswith('aes'):
        # Check for required AES fields
        if 'iv' not in encrypted_data:
            raise ValueError("Invalid AES encrypted data: missing IV")
            
        # Get the key from the encrypted data or use provided key
        if key is None and 'key' in encrypted_data:
            key = base64.b64decode(encrypted_data['key'])
            print("Using key from encrypted data")
        elif key is not None and isinstance(key, str):
            # Try to decode the key if it's a base64 string
            try:
                key = base64.b64decode(key)
                print(f"Decoded provided key (length: {len(key)} bytes)")
            except Exception as e:
                raise ValueError(f"Invalid key format: {str(e)}")
        
        if not key:
            raise ValueError("No decryption key provided or found in encrypted data")
            
        # Get key size from method or data
        if '-' in method:
            key_size = int(method.split('-')[1])
        else:
            key_size = encrypted_data.get('key_size', 256)
            
        # Check key length
        expected_key_bytes = key_size // 8
        if len(key) != expected_key_bytes:
            raise ValueError(f"Key must be {expected_key_bytes} bytes for AES-{key_size}, got {len(key)} bytes")
        
        print(f"Key validation passed. Using AES-{key_size} decryption")
        plaintext = decrypt_aes(encrypted_data, key)
        
    elif method == '3des-cbc':
        # Check for required 3DES fields
        if 'iv' not in encrypted_data:
            raise ValueError("Invalid 3DES encrypted data: missing IV")
            
        if key is None and 'key' in encrypted_data:
            key = base64.b64decode(encrypted_data['key'])
            print("Using key from encrypted data")
        elif key is not None and isinstance(key, str):
            # Try to decode the key if it's a base64 string
            try:
                key = base64.b64decode(key)
                print(f"Decoded provided key (length: {len(key)} bytes)")
            except Exception as e:
                raise ValueError(f"Invalid key format: {str(e)}")
        
        if not key:
            raise ValueError("No decryption key provided or found in encrypted data")
            
        # Check key length for 3DES
        if len(key) != 24:
            raise ValueError(f"Key must be 24 bytes for 3DES, got {len(key)} bytes")
        
        print("Key validation passed. Using 3DES decryption")
        plaintext = decrypt_3des(encrypted_data, key)
        
    elif method == 'rsa' or method == 'rsa+aes':
        # Check for required RSA fields
        if method == 'rsa+aes' and 'encrypted_symmetric_key' not in encrypted_data:
            raise ValueError("Invalid RSA encrypted data: missing encrypted symmetric key")
            
        if key is None and 'private_key' in encrypted_data:
            private_key = encrypted_data['private_key']
            print("Using private key from encrypted data")
        else:
            private_key = key
            print("Using provided private key")
            
        if not private_key:
            raise ValueError("No private key provided or found in encrypted data")
            
        print("Using RSA decryption")
        plaintext = decrypt_rsa(encrypted_data, private_key)
    else:
        raise ValueError(f"Unsupported encryption method: {method}")
    
    print(f"Decryption successful, produced {len(plaintext)} bytes of plaintext")
    return plaintext

# Sign a file with private key (for authentication)
def sign_file(data, private_key_pem):
    """Signs data with a private key for authentication purposes"""
    if isinstance(data, str):
        data = data.encode()
    
    # Load private key
    private_key = load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )
    
    # Create a signature
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode('utf-8')

# Verify a signature using public key
def verify_signature(data, signature, public_key_pem):
    """Verifies a signature using the corresponding public key"""
    if isinstance(data, str):
        data = data.encode()
    
    signature = base64.b64decode(signature)
    
    # Load public key
    public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
    
    try:
        # Verify the signature
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# Enhanced file encryption with optional signing
def encrypt_file_with_signing(file_data, method, key=None, signing_key=None, iv=None, original_filename=None):
    """Encrypts a file and optionally signs it with a private key for authentication"""
    # Get the original file encryption result
    encryption_result = encrypt_file(file_data, method, key, iv, original_filename)
    encrypted_data = json.loads(encryption_result)
    
    # If signing key is provided, add a signature
    if signing_key:
        # Sign the encrypted ciphertext to prove authenticity
        signature = sign_file(base64.b64decode(encrypted_data['ciphertext']), signing_key)
        encrypted_data['signature'] = signature
        encrypted_data['signed'] = True
    
    # Convert to JSON for storage
    return json.dumps(encrypted_data)

# Enhanced file decryption with signature verification
def decrypt_file_with_verification(encrypted_data_json, key=None, verification_key=None):
    """Decrypts a file and optionally verifies its signature for authentication"""
    encrypted_data = json.loads(encrypted_data_json)
    
    # Check if the file was signed
    signature_verified = None
    if verification_key and 'signature' in encrypted_data:
        # Verify the signature before decryption
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        signature = encrypted_data['signature']
        signature_verified = verify_signature(ciphertext, signature, verification_key)
    
    # Decrypt the file normally
    decrypted_data = decrypt_file(encrypted_data_json, key)
    
    # Return the decrypted data and verification status
    return {
        'data': decrypted_data,
        'signature_verified': signature_verified
    }