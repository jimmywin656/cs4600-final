from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import base64
import Sender
import Receiver

def get_secret_key():
    secret_key = input("Enter a secret key (K) that is known between both Sender & Receiver: ")
    return bytes(secret_key, 'utf-8')

def check_keys():
    print("Is this your first time running the program?")
    print("1) Yes? Generate RSA keys for both Sender and Receiver")
    print("2) No, continue with program.")
    while True:
        first_time = input().strip()
        if first_time in {"1", "2"}:
            if first_time == "1":
                return True
            else:
                return False
        else:
            print("Invalid choice. Please enter 1 or 2.")

def determine_sender():
    print("Will you be sending or receiving data?")
    print("1) Sending")
    print("2) Receiving")
    while True:
        role = input().strip()
        if role in {"1", "2"}:
            if role == "1":
                return True
            else:
                return False
        else:
            print("Invalid choice. Please enter 1 or 2.")

def generate_rsa_keys(filename):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(f"{filename}_private.pem", "wb") as file:
        file.write(private_key)
    with open(f"{filename}_public.pem", "wb") as file:
        file.write(public_key)

def main():
    # main text based program here
    secret_key = get_secret_key()       # used in mac

    has_keys = check_keys()
    if not has_keys:    # user does not have keys => generate keys for both sender + recevier
        generate_rsa_keys("sender")
        generate_rsa_keys("receiver")
    
    # determine if user is sender or receiver
    sender = determine_sender()
    if sender:
    # sender stuff here // get text, etc
        message = Sender.get_message()
        aes_key = get_random_bytes(32)  # 256-bit AES key , this can move to sender file as separate function called generate_aes_key()
        ciphertext, iv = Sender.encrypt_message(message, aes_key)       # bytes
        receiver_rsa_key = Sender.read_rsa_file("receiver_public.pem")
        e_aes_key = Sender.encrypt_aes_key(aes_key, receiver_rsa_key)
        mac = Sender.get_mac(ciphertext, iv, secret_key)
        # THINGS TO ADD TO transmitted_data.txt
        # encrypted message (ciphertext + iv)
        # encrypted aes key (using receiver pub key)
        # mac code
        # print(f"Message: {message}")
        # print(f"Ciphertext: {base64.b64encode(ciphertext).decode('utf-8')}")
        # decryped_message = Receiver.decrypt_message(ciphertext, iv, aes_key)
        # print(f"Decrypted message: {decryped_message}")

        # print(f"AES Key: {base64.b64encode(aes_key).decode('utf-8')}")
        # print(f"Encrypted AES Key: {base64.b64encode(e_aes_key).decode('utf-8')}")
        # priv_rsa_key = Receiver.read_rsa_file("receiver_private.pem")
        # decryped_aes_key = Receiver.decrypt_aes_key(e_aes_key, priv_rsa_key)
        # print(f"Decrypted AES Key: {base64.b64encode(decryped_aes_key).decode('utf-8')}")
        
        
        # print(f"MAC: {mac}")
        # r_mac = Receiver.get_mac(ciphertext, iv, secret_key)        # include ciphertext + iv in transmitted_data because MAC needs this
        # print(f"Receiver MAC: {r_mac}")

        # SAVE INFO TO transmitted_data.txt
        Sender.write_sender_file(ciphertext, iv, e_aes_key, mac)
    else:
        # receiver stuff here
        # assumes that a transmitted_data.txt file exists
        # original_ciphertext, original_iv, encrypted_aes_key, original_mac = Receiver.read_transmitted_data()
        # print()
        # priv_rsa_key = Receiver.read_rsa_file("receiver_private.pem")
        # decrypted_aes_key = Receiver.decrypt_aes_key(encrypted_aes_key, priv_rsa_key)
        # decrypted_message = Receiver.decrypt_message(original_ciphertext, original_iv, decrypted_aes_key)
        # new_mac = Receiver.get_mac(original_ciphertext, original_iv, secret_key)
        # if new_mac == original_mac:
        #     print("MACs are the same. Message AUTHENTICATED.")
        # print(decrypted_message)

if __name__ == '__main__':
    main()