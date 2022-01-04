import numpy as np
import hashlib as hl
import binascii
from Crypto.Cipher import AES
from base64 import b64encode
from base64 import b64decode
import json
import time
import threading

prime_order_p = 16069
generator_g = 21
lock = threading.Lock()
# semaphore = threading.Semaphore()


def user_action(g, p):
    secret = np.random.randint(2, 20)
    y = (g ** secret) % p
    return y, secret


def calculate_private_key(y, secret, p):
    lock.acquire()
    # pk =  np.mod((np.power(y, secret)), p)
    pk = (y ** secret) % p
    lock.release()
    return pk


def write_to_file(message: str):
    f = open("Communication.txt", "a")
    f.write(str(message) + "\n")
    f.close()


def append_fifteen_zeros_the_string(message: str):
    return message + "000000000000000"



def encrypt(key, message: str):
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


global K_ab_A


def get_user_input(message: str):

    y_A, secret_a = user_action(generator_g, prime_order_p)
    print("seca", secret_a)
    # Alice look if there is any. Else continue.
    f = open("Communication.txt", "a")
    f.write(str(y_A) + "\n")
    # print(y_A)
    f.close()
    f = open("Communication.txt", "r")
    f = np.genfromtxt("Communication.txt")
    while f.size <= 1:
        f = np.genfromtxt("Communication.txt")
        # semaphore.acquire()

        print("2 sec")


        # lock.release()
        # semaphore.release()
        time.sleep(2)
    lock.acquire()


    print("yes")
    # # TODO: Change this.
    f = open("Communication.txt", "r")
    lines = f.readlines()
    line = lines[1]
    y_B = int(line.strip())
    print("y_B", y_B)
    global K_ab_A
    K_ab_A = pow(y_B, secret_a, prime_order_p)
    # K_ab_A = calculate_private_key(y_B, secret_a, prime_order_p)
    lock.release()



global K_ab_B
def user2():
    # semaphore.acquire()
    lock.acquire()
    global K_ab_B
    message = input("Please enter username" + "\n")
    y_B, secret_b = user_action(generator_g, prime_order_p)
    print("secb", secret_b)
    print("y_B", y_B)
    f = open("Communication.txt", "a")
    f.write(str(y_B) + "\n")
    # print(y_A)
    f.close()
    # t1.join()
    f = open("Communication.txt", "r")
    line = f.readline()
    f.close()
    y_A2 = int(line.strip())

    # y_A2 = f[0]
    print("y_A2", y_A2)
    K_ab_B = pow(y_A2, secret_b, prime_order_p)
    print("k", K_ab_B)
    lock.release()
    # semaphore.release()

message = input("Please enter username" + "\n")
t1 = threading.Thread(target=get_user_input, args=("username",))
t1.start()
t2 = threading.Thread(target=user2)
t2.start()
t2.join()
t1.join()



print("k1",K_ab_A)
print(K_ab_B)
## Encrypted communication phase




# y_A, secret_a = user_action(generator_g, prime_order_p)



# K_ab_A = calculate_private_key(y_B, secret_a)
# K_ab_B = calculate_private_key(y_A, secret_b)

# f = open("Communication.txt", "a")
# f.write(str(y_A) + "\n")
# f.close()
def get_private_key(K_ab_A, K_ab_B):
    if K_ab_A == K_ab_B:
        hashed_string = hl.sha256(str(K_ab_A).encode('utf-8')).hexdigest()
        key = binascii.unhexlify(hashed_string)
        return key

key = get_private_key(K_ab_A, K_ab_B)
encrypted_message = encrypt(key, "hello")

decrypt(encrypted_message)


# Man in the middle
def man_in_the_middle(file1, file2):
    pass


file1 = "Communication_A.txt"
file2 = "Communication_B.txt"
man_in_the_middle(file1, file2)
