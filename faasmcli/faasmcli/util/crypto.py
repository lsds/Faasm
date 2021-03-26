import hashlib
import random
import string
from Cryptodome.Cipher import AES
from Crypto.Random import get_random_bytes
from faasmcli.util.constants import NONCE_SIZE, AES_KEY_SIZE, TAG_SIZE


def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = "".join(random.choice(letters) for i in range(length))
    return result_str


def encrypt_aes_gcm_128(
    msg, encryption_key, nonce_size=NONCE_SIZE, key_size=AES_KEY_SIZE
):
    nonce = get_random_bytes(nonce_size)
    aesCipher = AES.new(encryption_key[:key_size], AES.MODE_GCM, nonce=nonce)
    ciphertext, mac = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, nonce, mac)


def decrypt_aes_gcm_128(
    ciphertext,
    nonce,
    tag,
    decryption_key,
    nonce_size=NONCE_SIZE,
    key_size=AES_KEY_SIZE,
):
    aesCipher = AES.new(decryption_key[:key_size], AES.MODE_GCM, nonce=nonce)
    return aesCipher.decrypt_and_verify(ciphertext, tag)


def encrypt_file(
    module_path, output_path, nonce_size=NONCE_SIZE, key_size=AES_KEY_SIZE
) -> (
    str,
    str,
    str,
):  # encryptes given file with module path with nonce and tag
    with open(module_path, "rb") as f:
        bytes_read = f.read()
    key = get_random_string(AES_KEY_SIZE)
    nonce = get_random_bytes(nonce_size)
    cipher = AES.new(key.encode(), AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(bytes_read)
    f = open(output_path, "w+b")
    f.write(nonce + tag + ciphertext)
    f.close()
    return key


def get_file_hash_digest(
    file_path, offset=NONCE_SIZE + TAG_SIZE
) -> str:  # generates sha256 for file
    BLOCK_SIZE = 64 * 1024
    file_hash = (
        hashlib.sha256()
    )  # Create the hash object, can use something other than `.sha256()` if you wish
    with open(file_path, "rb") as f:  # Open the file to read it's bytes
        fb = f.read(
            BLOCK_SIZE
        )  # Read from the file. Take in the amount declared above
        while (
            len(fb) > 0
        ):  # While there is still data being read from the file
            file_hash.update(fb)  # Update the hash
            fb = f.read(BLOCK_SIZE)  # Read the next block from the file
    return file_hash.hexdigest()  # Get the hexadecimal digest of the hash
