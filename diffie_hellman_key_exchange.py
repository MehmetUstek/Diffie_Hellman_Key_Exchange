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


def generate_secret_and_g_a(g, p):
    secret = np.random.randint(2, 20)
    y = (g ** secret) % p
    return y, secret


def calculate_private_key(y, secret, p):
    lock.acquire()
    # pk =  np.mod((np.power(y, secret)), p)
    pk = (y ** secret) % p
    lock.release()
    return pk


def write_to_file(message: str, filename):
    f = open(filename, "a")
    f.write(str(message) + "\n")
    f.close()


def append_fifteen_zeros_the_string(message: str):
    return message + "000000000000000"



def encrypt(key, message: str, filename):
    data = bytes(message, encoding='utf-8')
    cipher = AES.new(key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(data)
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    ct_end_str = append_fifteen_zeros_the_string(ct)
    write_to_file(ct_end_str, filename)

    result = json.dumps({'nonce': nonce, 'ciphertext': ct})
    print(result)
    return result


# decrypt
def decrypt(json_input, key):
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


def get_user_input(file:str):

    y_A, secret_a = generate_secret_and_g_a(generator_g, prime_order_p)
    # Alice look if there is any. Else continue.
    f = open(file, "a")
    f.write(str(y_A) + "\n")
    f.close()
    f = open(file, "r")
    f = np.genfromtxt(file)
    while f.size <= 1:
        f = np.genfromtxt(file)

        time.sleep(1)
    lock.acquire()
    f = open(file, "r")
    lines = f.readlines()
    line = lines[1]
    y_B = int(line.strip())
    global K_ab_A
    K_ab_A = pow(y_B, secret_a, prime_order_p)
    # K_ab_A = calculate_private_key(y_B, secret_a, prime_order_p)
    lock.release()



global K_ab_B
def user2(file:str):
    # semaphore.acquire()
    lock.acquire()
    global K_ab_B
    y_B, secret_b = generate_secret_and_g_a(generator_g, prime_order_p)
    f = open(file, "a")
    f.write(str(y_B) + "\n")
    f.close()
    # t1.join()
    f = open(file, "r")
    line = f.readline()
    f.close()
    y_A2 = int(line.strip())

    # y_A2 = f[0]
    K_ab_B = pow(y_A2, secret_b, prime_order_p)
    lock.release()
    # semaphore.release()

username1 = input("Please enter username" + "\n")
t1 = threading.Thread(target=get_user_input, args=("Communication.txt",))
t1.start()
t2 = threading.Thread(target=user2, args= ("Communication.txt",))
username2 = input("Please enter username 2" + "\n")
t2.start()
t2.join()
t1.join()


## Encrypted communication phase

def get_private_key(K_ab_A, K_ab_B):
    if K_ab_A == K_ab_B:
        hashed_string = hl.sha256(str(K_ab_A).encode('utf-8')).hexdigest()
        key = binascii.unhexlify(hashed_string)
        return key


def user1_key(K_ab_A):
    hashed_string = hl.sha256(str(K_ab_A).encode('utf-8')).hexdigest()
    key = binascii.unhexlify(hashed_string)
    return key

def user2_key(K_ab_B):
    hashed_string = hl.sha256(str(K_ab_B).encode('utf-8')).hexdigest()
    key = binascii.unhexlify(hashed_string)
    return key

def user_send_message(message:str, key, filename):
    encrypted_message = encrypt(key, message, filename)
    return encrypted_message

# key = get_private_key(K_ab_A, K_ab_B)
def communication_phase(username1, username2, K_ab_A, K_ab_B, filename):
    input_from_user = " "
    user1Key = user1_key(K_ab_A)
    print("Alice's key", user1Key)
    user2Key = user2_key(K_ab_B)
    print("Bob's key", user2Key)
    while input_from_user != "-1":
        input_from_user = input(username1+"'s message:")

        encrypted_message = user_send_message(input_from_user, user1Key, filename)
        decrypt(encrypted_message, user2Key)
        input_from_user = input(username2+"'s message:")

        encrypted_message = user_send_message(input_from_user, user2Key, filename)
        decrypt(encrypted_message, user1Key)

communication_phase(username1, username2, K_ab_A, K_ab_B)
# decrypt(encrypted_message)

def copy_files_into_A_and_B(file1, file2):
    with open("Communication.txt") as f:
        with open(file1, "w") as f1:
            for line in f:
                f1.write(line)
    with open("Communication.txt") as f:
        with open(file2, "w") as f2:
            for line in f:
                f2.write(line)

# Man in the middle
def man_in_the_middle(file1, file2):
    # copy_files_into_A_and_B(file1, file2)
    print("########################")
    print("Man in the middle")
    # For Alice.
    username1 = input("Attacker username" + "\n")
    t1 = threading.Thread(target=get_user_input, args=(file1,))
    t1.start()
    t2 = threading.Thread(target=user2, args= (file1,))
    username2 = input("Please enter username" + "\n")
    t2.start()
    t2.join()
    t1.join()
    global K_ab_A, K_ab_B
    # First with alice
    communication_phase(username1, username2, K_ab_A, K_ab_B, file1)


    # For Bob




file1 = "Communication_A.txt"
file2 = "Communication_B.txt"
man_in_the_middle(file1, file2)
