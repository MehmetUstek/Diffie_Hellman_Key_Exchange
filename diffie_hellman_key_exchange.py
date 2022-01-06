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

# Given the generator g and prime order p, this function calculates the secret and
# the public key of the user.
# Namely, it randomly outputs a secret a, and calculates ga modulo p.
def generate_secret_and_g_a(g, p):
    secret = np.random.randint(10, 70)
    # y = (g ** secret) % p
    y = pow(g, secret, p)
    return y, secret


# Given the secret and the public key of the second party, the first party calculates its private key.
# The following function for calculation is just like the one before,
# ya modulo p = gab mod p.
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


# Given the key, message and the filename, this function encrypts the message
# using AES-128 CTR encryption, with a random nonce.
# Then the function from Crypto.Cipher library encrypts the message and returns a
# nonce and a ciphertext.
# I wrote these two values to the file with comma separation.
def encrypt(key, message: str, filename):
    data = bytes(message, encoding='utf-8')
    cipher = AES.new(key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(data)
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    ct_end_str = append_fifteen_zeros_the_string(ct)
    # write_to_file(ct_end_str, filename)

    result = json.dumps({'nonce': nonce, 'ciphertext': ct})
    str = nonce + "," + ct_end_str
    write_to_file(str, filename)
    # print(result)
    # print(str)

    return result


# decrypt
#  Takes the message written to the file and splits it into nonce and ciphertext.
#  Next, it decrypts the message using these two parameters with AES-128 CTR mode.
#  It then returns the plaintext.
def decrypt(username, message_input_from_file, key):
    try:
        # b64 = json.loads(json_input)
        # nonce = b64decode(b64['nonce'])
        # ct = b64decode(b64['ciphertext'])
        message_input_from_file = message_input_from_file.split(",")
        nonce = b64decode(message_input_from_file[0])
        ct = b64decode(message_input_from_file[1][:-15])

        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        pt = cipher.decrypt(ct)
        pt = bytes.decode(pt, encoding='utf-8')
        print(username + " received the ciphertext, the message was:", pt)

        return pt
    except (ValueError, KeyError):
        print("Incorrect decryption")


global K_ab_A


def get_user_input(file: str):
    y_A, secret_a = generate_secret_and_g_a(generator_g, prime_order_p)
    # Alice look if there is any. Else continue.
    f = open(file, "a")
    f.write(str(y_A) + "\n")
    f.close()
    # f = open(file, "r")
    f = np.genfromtxt(file)
    while f.size <= 1:
        f = np.genfromtxt(file)
        # TODO: Change to 10
        time.sleep(10)
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


def user2(file: str):
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


## Encrypted communication phase

# Unnecessary function.
def get_private_key(K_ab_A, K_ab_B):
    if K_ab_A == K_ab_B:
        hashed_string = hl.sha256(str(K_ab_A).encode('utf-8')).hexdigest()
        key = binascii.unhexlify(hashed_string)
        return key


# K_ab_A is the calculated private key, namely the g^ab mod p.
# This function returns the H(gab mod p) in an ascii form.
def user1_key(K_ab_A):
    hashed_string = hl.sha256(str(K_ab_A).encode('utf-8')).hexdigest()
    key = binascii.unhexlify(hashed_string)
    return key


# K_ab_B is the calculated private key, namely the g^ab mod p.
# This function returns the H(gab mod p) in an ascii form.
def user2_key(K_ab_B):
    hashed_string = hl.sha256(str(K_ab_B).encode('utf-8')).hexdigest()
    key = binascii.unhexlify(hashed_string)
    return key


def user_send_message(message: str, key, filename):
    encrypted_message = encrypt(key, message, filename)
    return encrypted_message


# key = get_private_key(K_ab_A, K_ab_B)
def communication_phase(username1, username2, K_ab_A, K_ab_B, filename):
    input_from_user = " "
    user1Key = user1_key(K_ab_A)
    print(username1 + "'s key", user1Key)
    user2Key = user2_key(K_ab_B)
    print(username2 + "'s key", user2Key)
    message_counter = 1
    print("This conversation will go on until one of the parties input -1.")
    while input_from_user != "-1":
        input_from_user = input(username1 + "'s message:")
        if input_from_user == "-1":
            break
        message_counter += 1
        dummy = user_send_message(input_from_user, user1Key, filename)
        encrypted_message = np.genfromtxt(filename, dtype="U")[message_counter]
        if not encrypted_message:
            time.sleep(10)
        else:
            # print("current_message", encrypted_message)
            decrypt(username2, encrypted_message, user2Key)
        input_from_user = input(username2 + "'s message:")
        message_counter += 1
        dummy = user_send_message(input_from_user, user2Key, filename)
        encrypted_message = np.genfromtxt(filename, dtype="U")[message_counter]
        if not encrypted_message:
            time.sleep(10)
        else:
            decrypt(username1, encrypted_message, user1Key)


def attacker_communication_phase(username1, username2, K_ab_A1, K_ab_B1, K_ab_A2, K_ab_B2, file1, file2):
    input_from_user = " "
    attackerKey_first_party = user1_key(K_ab_A)
    print("Attacker1's key with " + username1, attackerKey_first_party)
    userKey_first_party = user2_key(K_ab_B)
    print(username1 + "'s key", userKey_first_party)

    attackerKey_second_party = user1_key(K_ab_A)
    print("Attacker2's key with " + username2, attackerKey_second_party)
    userKey_second_party = user2_key(K_ab_B)
    print(username2 + "'s key", userKey_second_party)
    message_counter_1 = 1
    while input_from_user != "-1":
        input_from_user = input(username1 + "'s message:")
        if input_from_user == "-1":
            break
        message_counter_1 += 1
        dummy = user_send_message(input_from_user, userKey_first_party, file1)
        encrypted_message = np.genfromtxt(file1, dtype="U")[message_counter_1]
        if not encrypted_message:
            time.sleep(10)
        else:
            # print("current_message", encrypted_message)
            decrypt("Attacker", encrypted_message, attackerKey_first_party)
        # First, the message is taken from first party. Then encrypted with first party key.
        # encrypted_message = user_send_message(input_from_user, userKey_first_party, file1)
        # Then, the message is decrypted with attacker's key with first party.
        # decrypt(encrypted_message, attackerKey_first_party)
        # Then Attacker decides what to send to the second party.
        input_from_user = input("The message that will be sent to other party:")
        if input_from_user == "-1":
            break
        # Attacker encrypts his message with his own key.
        dummy = user_send_message(input_from_user, attackerKey_second_party, file2)
        encrypted_message = np.genfromtxt(file2, dtype="U")[message_counter_1]
        if not encrypted_message:
            time.sleep(10)
        else:
            # print("current_message", encrypted_message)
            # The second party decrypts the message with their own key.
            decrypt(username2, encrypted_message, userKey_second_party)

        # encrypted_message = user_send_message(input_from_user, attackerKey_second_party, file2)

        # decrypt(encrypted_message, userKey_second_party)

        # All above steps now for the second party sending messages.
        input_from_user = input(username2 + "'s message:")
        if input_from_user == "-1":
            break
        message_counter_1 += 1
        dummy = user_send_message(input_from_user, userKey_second_party, file2)
        encrypted_message = np.genfromtxt(file2, dtype="U")[message_counter_1]
        if not encrypted_message:
            time.sleep(10)
        else:
            # print("current_message", encrypted_message)
            decrypt("Attacker", encrypted_message, attackerKey_second_party)
        # encrypted_message = user_send_message(input_from_user, userKey_second_party, file2)
        # decrypt(encrypted_message, attackerKey_second_party)
        input_from_user = input("The message that will be sent to other party:")
        dummy = user_send_message(input_from_user, attackerKey_first_party, file1)
        encrypted_message = np.genfromtxt(file1, dtype="U")[message_counter_1]
        if not encrypted_message:
            time.sleep(10)
        else:
            # Again attacker will decrypt the message from second party, with his key for second party.
            decrypt(username1, encrypted_message, userKey_first_party)

        # encrypted_message = user_send_message(input_from_user, attackerKey_first_party, file1)
        # decrypt(encrypted_message, userKey_first_party)


# Cleaning the files before restart.
# f = open("Communication.txt", "w")
# f.close()
#
# username1 = input("Please enter username for user 1" + "\n")
# t1 = threading.Thread(target=get_user_input, args=("Communication.txt",))
# t1.start()
# t2 = threading.Thread(target=user2, args=("Communication.txt",))
# username2 = input("Please enter username for user 2" + "\n")
# t2.start()
# t2.join()
# t1.join()
# print("First Part Communication Phase")
# communication_phase(username1, username2, K_ab_A, K_ab_B, "Communication.txt")


# Unnecessary function
# def copy_files_into_A_and_B(file1, file2):
#     with open("Communication.txt") as f:
#         with open(file1, "w") as f1:
#             for line in f:
#                 f1.write(line)
#     with open("Communication.txt") as f:
#         with open(file2, "w") as f2:
#             for line in f:
#                 f2.write(line)


# Man in the middle
def man_in_the_middle(file1, file2):
    # copy_files_into_A_and_B(file1, file2)
    print("########################")
    print("Man in the middle")

    # For Alice.
    attacker_username1 = input("Please enter username for Attacker for user 1" + "\n")
    t1 = threading.Thread(target=get_user_input, args=(file1,))
    t1.start()
    t2 = threading.Thread(target=user2, args=(file1,))
    username1 = input("Please enter username for user 1" + "\n")
    t2.start()
    t2.join()
    t1.join()
    global K_ab_A, K_ab_B
    attacker_K_with_first_party = np.copy(K_ab_A)
    first_party_K = np.copy(K_ab_B)
    # First Alice got her keys with Attacker
    # Now, Bob will get his keys with the Attacker.

    attacker_username2 = input("Please enter username for Attacker for user 2" + "\n")
    t1 = threading.Thread(target=get_user_input, args=(file2,))
    t1.start()
    t2 = threading.Thread(target=user2, args=(file2,))
    username2 = input("Please enter username for user 2" + "\n")
    t2.start()
    t2.join()
    t1.join()
    attacker_K_with_second_party = np.copy(K_ab_A)
    second_party_K = np.copy(K_ab_B)
    # First with alice
    print("Man in the Middle Communication Phase")
    attacker_communication_phase(username1, username2, attacker_K_with_first_party, first_party_K,
                                 attacker_K_with_second_party, second_party_K, file1, file2)


# file1 = "Communication_A.txt"
# file2 = "Communication_B.txt"
# # Cleaning the files before restart.
# f = open(file1, "w")
# f.close()
# f = open(file2, "w")
# f.close()
# man_in_the_middle(file1, file2)

# The above part was single-file implementation.

# Two separate file implementation:

def get_user_input2(file: str, y_A, secret_a, sleep_time):
    f = np.genfromtxt(file)
    while f.size <= 1:
        f = np.genfromtxt(file)
        print("Waiting for the second party to enter!")
        time.sleep(sleep_time)


    lock.acquire()
    f = np.genfromtxt(file)
    index = np.where(f == y_A)[0][0]
    is_first_user = index == 0
    index = 0
    for i in f:
        if i != y_A:
            y_B = int(i)
    # f = open(file, "r")
    # lines = f.readlines()
    # line = lines[1]
    # y_B = int(line.strip())
    private_key = pow(y_B, secret_a, prime_order_p)
    # K_ab_A = calculate_private_key(y_B, secret_a, prime_order_p)
    lock.release()
    return  private_key, is_first_user

def communication_phase_multiple_files(username, hashed_private_key, is_first_user, file, sleep_time):
    input_from_user = ""
    pt = ""
    size = 2
    while input_from_user != "-1" or pt != "-1":
        if is_first_user:
            input_from_user = input(username + "'s message:")

            # Write message to the file.
            dummy = user_send_message(input_from_user, hashed_private_key, file)
            if input_from_user == "-1":
                break
            # Get the next message from second party.
            f = np.genfromtxt(file, dtype="U")
            size += 1
            while f.size <= size:
                f = np.genfromtxt(file)
                time.sleep(sleep_time)
                print("Waiting for the other party to send a message!")
            encrypted_message = np.genfromtxt(file, dtype="U")[size]
            if not encrypted_message:
                time.sleep(sleep_time)
            else:
                pt = decrypt(username, encrypted_message, hashed_private_key)
                size += 1
        else:
            f = np.genfromtxt(file, dtype="U")
            while f.size == size:
                f = np.genfromtxt(file)
                print("Waiting for other party")
                time.sleep(sleep_time)

            encrypted_message = np.genfromtxt(file, dtype="U")[size]
            if not encrypted_message:
                time.sleep(sleep_time)
            else:
                # print("current_message", encrypted_message)
                pt = decrypt(username, encrypted_message, hashed_private_key)
                if pt == "-1":
                    break
                size += 1
                input_from_user = input(username + "'s message:")
                dummy = user_send_message(input_from_user, hashed_private_key, file)
                size += 1


sleep_time = 1
def part1():
    filename = "Communication.txt"
    # Cleaning the files before restart.
    # f = open(filename, "w")
    # f.close()
    username = input("Please enter username" + "\n")
    # username = "A"
    y, secret = generate_secret_and_g_a(generator_g, prime_order_p)
    command = ""
    while command != "init":
        command = input("Please enter init to start." + "\n")
        if command == "init":
            break

    write_to_file(str(y), filename)
    private_key, is_first_user = get_user_input2(filename, y, secret, sleep_time)
    print(private_key)
    print("is_first?", is_first_user)
    userKey = user1_key(private_key)
    print(username + "'s hashed key:", userKey)
    communication_phase_multiple_files(username, userKey, is_first_user, filename, sleep_time)

# part1()
# Man in the middle part - Multiple Files
file1 = "Communication_A.txt"
file2 = "Communication_B.txt"
# Cleaning the files before restart.
# f = open(file1, "w")
# f.close()
# f = open(file2, "w")
# f.close()
def part2():
    print("################################")
    print("Man in the middle part")
    username = input("Please enter username" + "\n")
    # username = "A"
    y, secret = generate_secret_and_g_a(generator_g, prime_order_p)
    command = ""
    while command != "init":
        command = input("Please enter init to start." + "\n")
        if command == "init":
            break
    f = np.genfromtxt(file1)
    if f.size == 0:
        file = file1
    else:
        file = file2
    write_to_file(str(y), file)
    private_key, is_first_user = get_user_input2(file, y, secret, sleep_time)
    print(private_key)
    print("is_first?", is_first_user)
    userKey = user1_key(private_key)
    print(username + "'s hashed key:", userKey)
    communication_phase_multiple_files(username, userKey, is_first_user, file, sleep_time)

# part2()