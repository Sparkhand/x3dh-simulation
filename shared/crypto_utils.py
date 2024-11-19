from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

class DHParams:
    """A data structure to hold Diffie-Hellman parameters and keys."""
    def __init__(self, p = None, g = None, private_key = None, public_key = None):
        self.p = p
        self.g = g
        self.private_key = private_key
        self.public_key = public_key

class Keyring:
    """A data structure to hold the three shared keys."""
    def __init__(self, sh_k1 = None, sh_k2 = None, sh_k3 = None):
        self.SH_K1 = sh_k1
        self.SH_K2 = sh_k2
        self.SH_K3 = sh_k3

def generate_dh_params(bits=1024):
    """Generate Diffie-Hellman parameters P and G."""
    p = getPrime(bits)
    g = 2
    return p, g

def generate_keys(p, g, bits=1024):
    """Generate a private key and a public key starting from P and G."""
    private_key = int.from_bytes(get_random_bytes(bits), 'big')
    public_key = pow(g, private_key, p)
    return private_key, public_key

def compute_shared_key(private_key, other_public_key, p):
    """Compute the DH shared key starting from the private key and the other's public key."""
    return pow(other_public_key, private_key, p)

def kdf(keyring):
    """Derive a cryptographic key (shared secret) from the three shared keys."""

    # Combine the three shared keys and hash them
    combined_key = str(keyring.SH_K1) + str(keyring.SH_K2) + str(keyring.SH_K3)
    hash_obj = SHA256.new()
    hash_obj.update(combined_key.encode('utf-8'))

    # Derive the key
    derived_key = hash_obj.digest()

    return derived_key


def encrypt_message(message, key):
    """Encrypt a message using AES-CBC with a given key."""

    # Check if message is already a bytes object
    if not isinstance(message, bytes):
        message = message.encode()

    # Create an AES cipher object with the key and a random IV
    cipher = AES.new(key, AES.MODE_CBC)

    # Add padding to the message and encrypt it
    ct_bytes = cipher.encrypt(pad(message, AES.block_size))

    # Return the IV and the ciphertext as a base64-encoded string
    return b64encode(cipher.iv + ct_bytes).decode('utf-8')

def decrypt_message(cipher_text, key):
    """Decrypt a message using AES-CBC with a given key."""

    # Decode the base64-encoded string
    ct = b64decode(cipher_text)

    # The IV was sent along with the ciphertext, so extract it
    iv = ct[:AES.block_size]
    ct = ct[AES.block_size:]

    # Create an AES cipher object with the key and the IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext and remove the padding
    pt = unpad(cipher.decrypt(ct), AES.block_size)

    return pt.decode('utf-8')
