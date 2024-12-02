from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
import base64
import hmac
from hashlib import sha256

# Reference:
# https://www.pycryptodome.org/src/cipher/pkcs1_v1_5

def get_message():
    message = input("Message to Receiver:\n")
    return message

def encrypt_message(message, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    iv = cipher.iv
    padded_message = pad(message.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    # return base64.b64encode(ciphertext).decode('utf-8'), base64.b64encode(iv).decode('utf-8')       # need to encode then decode to view as a string // iv used in mac algo
    return ciphertext, iv       # returns as bytes

def get_mac(ciphertext, iv, mac_key):
    message = iv + ciphertext
    mac = hmac.new(mac_key, message, sha256).hexdigest()    # assumes ciphertext + iv are bytes
    return mac

# include writing this to transmitted_data.txt
def write_sender_file(ciphertext, iv, e_aes_key, mac_code):
    ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    iv = base64.b64encode(iv).decode('utf-8')
    e_aes_key = base64.b64encode(e_aes_key).decode('utf-8')

    with open("transmitted_data.txt", "w") as file:
        file.write(ciphertext)
        file.write('\n')
        
        file.write(iv)
        file.write('\n')
        
        file.write(e_aes_key)
        file.write('\n')
        
        file.write(mac_code)
        file.write('\n')

def encrypt_aes_key(aes_key, rsa_key):
    cipher = PKCS1_v1_5.new(rsa_key)
    encrypted_aes_key = cipher.encrypt(aes_key)
    return encrypted_aes_key

def read_rsa_file(public_key_file):
    public_key = RSA.importKey(open(public_key_file).read())
    return public_key
