import diffie_hellman_key_exchange as dh
import numpy as np
import time
prime_order_p = 16069
generator_g = 21
sleep_time = dh.sleep_time

file1 = "Communication_A.txt"
file2 = "Communication_B.txt"

def get_private_key_from_user(file: str, y_A, secret_a, sleep_time):
    f = np.genfromtxt(file)
    while f.size <= 1:
        f = np.genfromtxt(file)
        print("Waiting for the second party to enter!")
        time.sleep(sleep_time)

    f = np.genfromtxt(file)
    for i in f:
        if i != y_A:
            y_B = int(i)
    private_key = pow(y_B, secret_a, prime_order_p)
    return  private_key

def maninmid_communication_phase(username, hashed_private_key1, hashed_private_key2, is_first_user, file1, file2, sleep_time):
    input_from_user = ""
    pt = ""
    size1 = 2
    size2 = 2
    while input_from_user != "-1" or pt != "-1":
        f = np.genfromtxt(file1, dtype="U")
        while f.size == size1:
            f = np.genfromtxt(file1)
            print("Waiting for other party")
            time.sleep(sleep_time)

        encrypted_message = np.genfromtxt(file1, dtype="U")[size1]
        if not encrypted_message:
            time.sleep(sleep_time)
        else:
            # print("current_message", encrypted_message)
            pt = dh.decrypt(username, encrypted_message, hashed_private_key1)
            if pt == "-1":
                break
            size1 += 1
            # Attacker sends whatever he wants to the second party
            input_from_user = input("Attacker's message to the other party:")
            dummy = dh.user_send_message(input_from_user, hashed_private_key2, file2)


            # Now attacker waits the response of second party.

            f = np.genfromtxt(file2, dtype="U")
            while f.size == size2:
                f = np.genfromtxt(file2)
                print("Waiting for other party")
                time.sleep(sleep_time)

            encrypted_message = np.genfromtxt(file2, dtype="U")[size2]
            if not encrypted_message:
                time.sleep(sleep_time)
            else:
                # print("current_message", encrypted_message)
                pt = dh.decrypt(username, encrypted_message, hashed_private_key1)
                if pt == "-1":
                    break
                size2 += 1
                # Attacker sends whatever he wants to the first party
                input_from_user = input("Attacker's message to the other party:")
                dummy = dh.user_send_message(input_from_user, hashed_private_key1, file1)


            input_from_user = input(username + "'s message:")
            dummy = dh.user_send_message(input_from_user, hashed_private_key1, file1)
            size1 += 1



def man_in_middle():
    username = input("Please enter Attacker username:" + "\n")
    # username = "A"
    y, secret = dh.generate_secret_and_g_a(generator_g, prime_order_p)
    command = ""
    while command != "init":
        command = input("Please enter init to start." + "\n")
        if command == "init":
            break
    is_first_user = False
    userKey1 = ""
    while userKey1 == "":
        f = np.genfromtxt(file1)
        if f.size != 0:
            dh.write_to_file(str(y), file1)
            dh.write_to_file(str(y), file2)
            private_key1 = get_private_key_from_user(file1, y, secret, sleep_time)
            print(private_key1)
            print(private_key1)
            print("is_first?", is_first_user)
            userKey1 = dh.user1_key(private_key1)
            print(username + "'s hashed key:", userKey1)

    # f = np.genfromtxt(file2)
    userKey2 = ""
    while userKey2 == "":
        f = np.genfromtxt(file2)
        if f.size != 0:

            private_key2 = get_private_key_from_user(file2, y, secret, sleep_time)
            print(private_key2)
            print(private_key2)
            print("is_first?", is_first_user)
            userKey2 = dh.user1_key(private_key2)
            print(username + "'s hashed key:", userKey2)
        time.sleep(sleep_time)


    maninmid_communication_phase(username, userKey1, userKey2, is_first_user, file1, file2, sleep_time)

man_in_middle()