import base64
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hmac
from hashlib import sha256

def read_transmitted_data():    # assumes the filename will always be transmitted_data
    with open('transmitted_data.txt', 'r') as file:
        content = file.read().splitlines()

        ciphertext = base64.b64decode(content[0])
        iv = base64.b64decode(content[1])
        original_aes_key = base64.b64decode(content[2])
        original_mac = base64.b64decode(content[3])
    return ciphertext, iv, original_aes_key, original_mac      

def decrypt_message(ciphertext, iv, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode('utf-8')

def get_mac(ciphertext, iv, mac_key):
    message = iv + ciphertext
    mac = hmac.new(mac_key, message, sha256).hexdigest()    # assumes ciphertext + iv are bytes
    return mac

def decrypt_aes_key(aes_key, priv_rsa_key):
    sentinel = get_random_bytes(32)
    cipher = PKCS1_v1_5.new(priv_rsa_key)
    original_aes_key = cipher.decrypt(aes_key, sentinel)    # The AES key is the random sentinel in case of error
    return original_aes_key

def read_rsa_file(private_key_file):
    private_key = RSA.importKey(open(private_key_file).read())
    return private_key