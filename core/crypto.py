from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, ciphers, padding as prim_padding
from os import urandom


def genkey():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key


def serialize(pub):
    public_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_pem


def deserialize(pem):
    public_key = serialization.load_pem_public_key(pem)
    return public_key


def encrypt(msg, pub):
    ciphertext = pub.encrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext


def decrypt(msg, priv):
    decrypted_message = priv.decrypt(
        msg,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_message

def gen_session_key():
    return urandom(32)

def encrypt_aes(msg, symmetric_key):
    iv = urandom(16)

    padder = prim_padding.PKCS7(128).padder() # ОШИБКА НЕ НАЙДЕТ PKCS7
    padded_data = padder.update(msg)
    padded_data += padder.finalize()


    core = ciphers.Cipher(ciphers.algorithms.AES(symmetric_key), ciphers.modes.CBC(iv))
    encryptor = core.encryptor()
    ciphertext = iv + encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext

def decrypt_aes(ciphertext, symmetric_key):
    iv = ciphertext[:16]
    pure_ciphertext = ciphertext[16:]

    core = ciphers.Cipher(ciphers.algorithms.AES(symmetric_key), ciphers.modes.CBC(iv))
    decryptor = core.decryptor()

    padded_data = decryptor.update(pure_ciphertext) + decryptor.finalize()

    unpadder = prim_padding.PKCS7(128).unpadder()
    msg = unpadder.update(padded_data)
    msg += unpadder.finalize()

    return msg