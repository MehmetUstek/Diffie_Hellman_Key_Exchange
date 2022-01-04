import numpy as np
import hashlib as hl
import binascii
from Crypto.Cipher import AES
from base64 import b64encode
from base64 import b64decode
import json
import time

prime_order_p = 299975359
generator_g = 53


def user_action(g, p):
    secret = np.random.randint(1, 20)
    y = (g ** secret) % p
    return y, secret


def calculate_private_key(y, secret):
    return y ** secret % prime_order_p


def write_to_file(message: str):
    f = open("Communication.txt", "a")
    f.write(str(message) + "\n")
    f.close()


def append_fifteen_zeros_the_string(message: str):
    return message + "000000000000000"


## Encrypted communication phase
def encrypt(message: str):
    data = bytes(message, encoding='utf-8')
    cipher = AES.new(key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(data)
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    ct_end_str = append_fifteen_zeros_the_string(ct)
    write_to_file(ct_end_str)

    result = json.dumps({'nonce': nonce, 'ciphertext': ct})
    print(result)
    return result


# decrypt
def decrypt(json_input):
    try:
        b64 = json.loads(json_input)
        nonce = b64decode(b64['nonce'])
        ct = b64decode(b64['ciphertext'])

        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        pt = cipher.decrypt(ct)
        pt = bytes.decode(pt, encoding='utf-8')
        print("The message was: ", pt)

        return pt
    except (ValueError, KeyError):
        print("Incorrect decryption")


y_A, secret_a = user_action(generator_g, prime_order_p)
y_B, secret_b = user_action(generator_g, prime_order_p)

input_username = "Alice"

K_ab_A = calculate_private_key(y_B, secret_a)
K_ab_B = calculate_private_key(y_A, secret_b)

f = open("Communication.txt", "a")
f.write(str(y_A) + "\n")
f.close()

t_end = time.time() + 60 * 15
while True:
    # Add 10-second wait in here. While another party continues.
    f = np.asarray(np.genfromtxt("Communication.txt", dtype='U'))
    print("10 sec")
    if f.size > 1:
        print("yes")
        break
    time.sleep(10)

if K_ab_A == K_ab_B:
    hashed_string = hl.sha256(str(K_ab_A).encode('utf-8')).hexdigest()
    print(hashed_string)
    print(K_ab_A)
    # f = open("Communication.txt", "a")
    # f.write(hashed_string + "\n")
    # f.close()
print(len(hashed_string))
key = binascii.unhexlify(hashed_string)

encrypted_message = encrypt("hello")

decrypt(encrypted_message)


# Man in the middle
def man_in_the_middle(file1, file2):
    pass


file1 = "Communication_A.txt"
file2 = "Communication_B.txt"
man_in_the_middle(file1, file2)
