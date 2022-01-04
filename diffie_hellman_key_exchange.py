import numpy as np
import hashlib as hl
import binascii
from Crypto.Cipher import AES
from base64 import b64encode
from base64 import b64decode
import json
prime_order_p = 299975359
generator_g = 53

input_username = "Alice"

secret_a = np.random.randint(1,20)
y_A = (generator_g**secret_a) % prime_order_p

secret_b = np.random.randint(1,20)
y_B = (generator_g ** secret_b) % prime_order_p

K_ab_A = y_B**secret_a % prime_order_p
K_ab_B = y_A**secret_b % prime_order_p

f = open("Communication.txt", "a")
f.write(str(y_A) + "\n")
f.close()


# Add 10-second wait in here. While another party continues.
f = np.asarray(np.genfromtxt("Communication.txt", dtype='U'))
if f.size > 1:
    print("yes")
    # break



if K_ab_A == K_ab_B:
    hashed_string = hl.sha256(str(K_ab_A).encode('utf-8')).hexdigest()
    print(hashed_string)
    print(K_ab_A)
    # f = open("Communication.txt", "a")
    # f.write(hashed_string + "\n")
    # f.close()
print(len(hashed_string))
key = binascii.unhexlify(hashed_string)
data = b"Hello canimmmm"
cipher = AES.new(key, AES.MODE_CTR)
ct_bytes = cipher.encrypt(data)
nonce = b64encode(cipher.nonce).decode('utf-8')
ct = b64encode(ct_bytes).decode('utf-8')
result = json.dumps({'nonce':nonce, 'ciphertext':ct})
print(result)

json_input = result
# decrypt
try:
    b64 = json.loads(json_input)
    nonce = b64decode(b64['nonce'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    pt = cipher.decrypt(ct)
    print("The message was: ", pt)
except (ValueError, KeyError):
    print("Incorrect decryption")