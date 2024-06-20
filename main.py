import getpass, bcrypt, sqlite3, os, random, string, pyperclip
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_passwd():
    a1 = list(string.ascii_lowercase)
    a2 = list(string.ascii_uppercase)
    a3 = list(string.digits)
    a4 = list(string.punctuation)
    res = ''
    x = 0
    for _ in range(10):
        y = random.randint(1,4)
        if y == x:
            y += 1
        match y:
            case 1:
                res  += random.choice(a1)
            case 2:
                res  += random.choice(a2)
            case 3:
                res  += random.choice(a3)
            case _:
                res  += random.choice(a4)
        x = y
    return res


def get_choice() -> int:
    while True:
        try:
            res = int(input("Enter your choice: "))
            return res
        except:
            print("!!!Please enter a number!!!")

def encode_passwd(passwd, key):
    # Set the encryption algorithm and mode
    algorithm1 = algorithms.AES(key)
    iv = os.urandom(16)  # Generate a random 16-byte IV
    mode = modes.CBC(iv)
    # Create a cipher contextpyperclip
    cipher = Cipher(algorithm1, mode, backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(passwd.encode()) + padder.finalize()
    return iv + encryptor.update(padded_data) + encryptor.finalize()
    
def decode_passwd(encrypted_passwd, key):
    algorithm1 = algorithms.AES(key)
    iv = encrypted_passwd[:16]
    encrypted_passwd = encrypted_passwd[16:]
    cipher = Cipher(algorithm1, modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_passwd) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(decrypted_padded_data) + unpadder.finalize()).decode()

def view_passwd(master_name, key):
    connection = sqlite3.connect("passwd_list.db")
    cursor = connection.cursor()
    temp = True
    while temp:
        print("1 VEIW ALL PASSWORD\n2 ACCORDING TO SITE AND EMAIL\n3 ACCORDING TO EMAIL\n4 QUIT")
        choice = get_choice()
        if choice == 1:
            query = f"SELECT * FROM {master_name}"
            try:
                cursor.execute(query)
            except:
                print(f"#####NO password added#####")
                return
            detail_list = cursor.fetchall()
            for detail in detail_list:   #detail = (id, site, username, email, enc_passwd)
                decrypted_passwd = decode_passwd(encrypted_passwd=detail[4], key=key)
                print(f"{detail[0]}. site: {detail[1]}, user name: {detail[2]}\nemail: {detail[3]}, password: {decrypted_passwd}")
                print("##############")
        elif choice == 2:
            tmp = True
            while tmp:
                email = input("Enter email: ")
                if len(email) == 0:   #not entered email
                    site = input("Enter site or app name: ")
                    if len(site) == 0:
                        print("!!!Please enter email or site or app name!!!")
                        continue
                    else:  #site entered
                        query = f"SELECT * FROM {master_name} WHERE site = ?"
                        try:
                            cursor.execute(query, (site,))
                        except:
                            print(f"#NO password added#")
                            return
                        detail_list = cursor.fetchall()
                        if len(detail_list) == 0:
                            print("!!!No site found!!!")
                            continue
                        for index, detail in enumerate(detail_list):      #detail = (id, site, username, email, enc_passwd)  
                            print(f"{index + 1}. username: {detail[2]}, Email: {detail[3]}")
                        while True:
                            print("!!enter index to copy the password to clip board!!")
                            choice1 = get_choice()
                            if choice1 in range(1, len(detail_list) + 1):
                                encypted_passwd = detail_list[choice1 - 1][4]
                                decrypted_passwd = decode_passwd(encypted_passwd, key)
                                pyperclip.copy(decrypted_passwd)
                                print("!!!Password copied to clipboard!!!")
                                tmp = False
                                break
                            else:
                                print("!!!Invalid index!!!")
                else:    #entered some email
                    query = f"SELECT * FROM {master_name} WHERE email = ?"
                    try:
                        cursor.execute(query, (email,))
                    except:
                        print(f"#####NO password added#####")
                        return
                    detail_list = cursor.fetchall()
                    if len(detail_list) == 0:
                        print("!!!No email found!!!")
                        continue
                    for index, detail in enumerate(detail_list):      #detail = (id, site, username, email, encryp_passwd)
                        print(f"{index + 1}. site: {detail[1]}, username: {detail[2]}")
                        while True:
                            print("!!enter index to copy the password to clip board!!")
                            choice1 = get_choice()
                            if choice1 in range(1, len(detail_list) + 1):
                                encypted_passwd = detail_list[choice1 - 1][4]
                                decrypted_passwd = decode_passwd(encypted_passwd, key)
                                pyperclip.copy(decrypted_passwd)
                                print("!!!Password copied to clipboard!!!")
                                tmp = False
                                break
                            else:
                                print("!!!Invalid index!!!")
        elif choice == 3:
            # View passwords according to email
            email = input("Enter email: ")
            query = f"SELECT * FROM {master_name} WHERE email = ?"
            cursor.execute(query, (email,))
            detail_list = cursor.fetchall()
            for detail in detail_list:
                decrypted_passwd = decode_passwd(encrypted_passwd=detail[4], key=key)
                print(f"{detail[0]}. site: {detail[1]}, user name: {detail[2]}\nemail: {detail[3]}, password: {decrypted_passwd}")

        elif choice == 4:
            return
        else:
            print("Invalid choice")


def add_passwd(master_name, key):
    connection = sqlite3.connect("passwd_list.db")
    cursor = connection.cursor()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {master_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NULL,
            username TEXT NULL,
            email TEXT NULL,
            encrypted_passwd BLOB NOT NULL
        );
    """)
    print("if you want to not give data press enter!")
    while True:
        site = input("enter site or app your using password: ")
        username = input("enter user name: ")
        email = input("enter email: ")
        if len(site) == 0 and len(username) == 0:
            print("pleas enter site name or user name!")
        else:
            break
    while True:
        print("1 TO GENERATE STRONG PASSWORD\n2 TO SAVE YOUR OWN PASSWORD")
        choice = get_choice()
        if choice == 1:
            passwd = generate_passwd()
            print("password is generated and added to your clipboard!")
            pyperclip.copy(passwd)
            break
        elif choice != 2:
            print("Invalid choice")
            continue
        passwd = getpass.getpass()
        if len(passwd) > 7:
            passwd_check = getpass.getpass("Enter password again: ")
            if passwd == passwd_check:
                break
            else:
                print("Password entered not matched")
        else:
            print("password need to be atleast 8 char!!!")

    encoded_passwd = encode_passwd(passwd, key)
    query = f"INSERT INTO {master_name} (site, username, email, encrypted_passwd) VALUES (?, ?, ?, ?)"
    datas = [site, username, email, encoded_passwd]
    for data in datas:
        if len(data) == 0:
            datas[datas.index(data)] = "!!not entered!!"
    cursor.execute(query, datas)
    connection.commit()
    connection.close()
    print("password added successfully!")
    return 

def login() -> str:
    count = 0
    tmp = True
    connection = sqlite3.connect("users_list.db")
    cursor = connection.cursor()
    while tmp:
        name_entered = input("enter your user name: ")
        cursor.execute("SELECT user_name FROM users")
        name_list = cursor.fetchall()
        for name in name_list:
            if name[0] == name_entered:
                tmp = False
                break
        else:
            print("user name not found!")
            count += 1
            if count > 2:
                res = int(input("1 MENU/n2 TRY AGAIN"))
                if res == 1:
                    return None, None, None, False     
                                              
    passwd = getpass.getpass()
    query = "SELECT hashed_passwd, salt FROM users WHERE user_name = ?"
    cursor.execute(query, (name_entered,))
    data = cursor.fetchone()
    stored_hashed_passwd = data[0]
    salt = data[1]
    entered_hashed_passwd = bcrypt.hashpw(passwd.encode(), salt)
    if entered_hashed_passwd == stored_hashed_passwd:
        print("###passwd correct logined###")
        return passwd, name_entered, salt, True
    else:
        return None, None, None, False

def re_encrypt_saved_passwd(old_key, new_key, master_name):
    connection = sqlite3.connect("passwd_list.db")
    cursor = connection.cursor()
    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS {master_name} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NULL,
            username TEXT NULL,
            email TEXT NULL,
            encrypted_passwd BLOB NOT NULL
        );
    """)
    query = f"SELECT encrypted_passwd FROM {master_name}"
    cursor.execute(query)
    stored_encrypted_passwd_list = cursor.fetchall()
    print(stored_encrypted_passwd_list)
    for stored_encrypted_passwd in stored_encrypted_passwd_list:
        encrypted_passwd = stored_encrypted_passwd[0]
        # print(f"Stored encrypted passwd: {encrypted_passwd}")
        decrypted_passwd = decode_passwd(encrypted_passwd, old_key)  #decode_passwd(encrypted_passwd=detail[4], key=key)
        # print(f"Decrypted passwd: {decrypted_passwd}")
        new_encrypted_passwd = encode_passwd(decrypted_passwd, new_key)
        query = f"UPDATE {master_name} SET encrypted_passwd = ? WHERE encrypted_passwd = ?"
        cursor.execute(query, (new_encrypted_passwd, encrypted_passwd))
    connection.commit()
    connection.close()
    print("###passwd re-encrypted###")
    return

def change_master_passwd():
    print("### CHANGING MASTER PASSWORD ###")
    connection = sqlite3.connect("users_list.db")
    cursor = connection.cursor()
    tmp = 0
    while True:
        user_name_entered = input("Enter your user name again: ")
        query = f"SELECT COUNT(*) FROM users WHERE user_name = ?"
        cursor.execute(query, (user_name_entered,))
        count = cursor.fetchone()[0]
        if count == 0:
            tmp += 1
            print("user name not found!")
            if tmp > 3:
                return
        else:
            user_name = user_name_entered
            break
    query = "SELECT hashed_passwd, salt FROM users WHERE user_name = ?"
    cursor.execute(query, (user_name,))
    data = cursor.fetchone()
    stored_hashed_passwd = data[0]
    salt = data[1]
    tmp1 = True
    count1 = 0
    while tmp1:
        old_passwd = getpass.getpass("Enter the old password: ")
        entered_hashed_passwd = bcrypt.hashpw(old_passwd.encode(), salt)
        if entered_hashed_passwd == stored_hashed_passwd:
            while True:
                new_passwd = getpass.getpass("Enter the new password: ")
                _ = getpass.getpass("Enter new password again: ")
                if new_passwd == _:
                    tmp1 = False
                    break
                else:
                    print("###passwords do not match###")
        else:   #old passwd not correct
            count1 += 1
            print("!!! Entered old password is wrong !!!")
            if count1 > 3:
                return

    new_salt = bcrypt.gensalt()
    new_hashed_passwd = bcrypt.hashpw(new_passwd.encode(), new_salt)
    query = "UPDATE users SET hashed_passwd = ?, salt = ? WHERE user_name = ?"
    cursor.execute(query, (new_hashed_passwd, new_salt, user_name))
    connection.commit()
    connection.close()
    kdf_old = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    old_key = kdf_old.derive(old_passwd.encode())
    kdf_new = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=new_salt,
        iterations=100000
    )
    new_key = kdf_new.derive(new_passwd.encode())
    re_encrypt_saved_passwd(old_key=old_key, new_key=new_key, master_name=user_name)
    print("###password changed###")
    return True

def sign_in():
    connection = sqlite3.connect("users_list.db")
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_name TEXT NOT NULL,
            hashed_passwd BLOB NOT NULL,
            salt BLOB NOT NULL
        );
    """)
    #for entering user name
    while True:
        entered_name = input("enter your new user name: ")
        cursor.execute("SELECT user_name FROM users")
        stored_names = cursor.fetchall()
        for stored_name in stored_names:
            if entered_name == stored_name[0]:
                print("user name already taken, pleas try other unique name")
                break
        else:
            print("valid user name!")
            break
    #for enterin passwd
    while True:
        passwd = getpass.getpass()
        if len(passwd) < 8:
            print("password need to be at least 8 char long!")
        else:
            passwd_check = getpass.getpass("Enter password again: ")
            if passwd == passwd_check:
                break
            else:
                print("Password entered not matched")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(passwd.encode(), salt)
    qury = "INSERT INTO users (user_name, hashed_passwd, salt) VALUES (?, ?, ?)"
    cursor.execute(qury, (entered_name, hashed_password, salt))
    connection.commit()
    cursor.close()
    connection.close()

def main() -> None:
    while True:
        print("1 LOGIN\n2 SIGN IN\n3 QUIT")
        choice = get_choice()
        if choice == 1:     #LOGIN
            master_passwd, master_name, salt, is_logined = login()
            if is_logined:  # AFTER LOGINED
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000
                )
                key = kdf.derive(master_passwd.encode())
                while True:
                    print("1 VIEW PASSWORD\n2 ADD PASSWORD\n3 CHANGE MASTER PASSWORD\n4 LOG OUT")
                    choice_1 = get_choice()
                    if choice_1 == 1:    #VIEW PASSWD
                        view_passwd(master_name, key)
                    elif choice_1 == 2:    #ADD PASSWD
                        add_passwd(master_name, key)
                    elif choice_1 == 3:
                        res = change_master_passwd()
                        if res:
                            break
                    elif choice_1 == 4:
                        break
                    else:
                        print("invalid choice!")
            else:
                print ("wrong password")
                continue
        elif choice ==  2:
            sign_in()
        elif choice == 3:
            return
        else:
            print("invalid number")

if __name__ == "__main__":
    main()