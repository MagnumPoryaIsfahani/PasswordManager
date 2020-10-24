import os
import json
import string
import getpass
import random
import bcrypt
import pyperclip

#MAIN FUNCTIONS
def mainMenu():

    while True:
        selection = input("Select an option below.\n1.Registration\n2.Login\nq.Quit\nSelection: ")
        acceptable = ['1','2', 'q']
 
        while(selection not in acceptable):
            selection = input("Invalid\nSelect an option below.\n1.Registration\n2.Login\nSelection: ")

        if(selection == '1'):
            register()
        elif(selection == '2'):
            login()
        else:
            quit()

def userMenu(username):
    while True:
        selection = input("Select an option below.\n1.Add Pass\n2.Delete Pass\n3.Delete Account\n4.Get Pass\nq.Quit\nSelection: ")
        acceptable = ['1','2','3','4','q']
 
        while(selection not in acceptable):
            selection = input("Invalid\nSelect an option below.\n1.Add Pass\n2.Delete Pass\n3.Delete Account\n4.Get Pass\nSelection: ")

        if(selection == '1'):
            addPass(username)
        elif(selection == '2'):
            deletePass(username)
        elif(selection == '3'):
            deleteUser(username)
            return
        elif(selection == '4'):
            getPass(username)
        else:
            quit()

def register():
    print("Registration...\n")

    username = input("Enter a Username: ")
    user_entries = getDB()

    while(username in user_entries):  
        username = input("Username already exists...\nEnter a Username: ")
    
    password =  getpass.getpass("Enter a password for your account: ")
    confirm_password =  getpass.getpass("Please confirm your password by retyping: ")

    while password != confirm_password:
        print("Your passwords don't match, please try again")
        password =  getpass.getpass("Enter a password for your account: ")
        confirm_password =  getpass.getpass("Please confirm your password by retyping: ")

    hashed_binary = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    password = hashed_binary.decode(encoding="utf-8")

    user_entries[username] = {"password": password}

    writeToDB(user_entries)

    print("Returning to main menu...\n")

def login():
    print("Login...\n")

    user_entries = getDB()

    while True:
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        if(username in user_entries):
            stored_hash = user_entries[username]['password']
            is_valid_creditials = bcrypt.checkpw(password.encode(), stored_hash.encode())
            if(is_valid_creditials):
                print("Logging in...")
                userMenu(username)
                return
            else:
                print("Password mismatch")
        else:
            print("Username does not exist...")

def addPass(username):
    user_entries = getDB()

    account = input("Enter an account: ")
    length = input("Enter a password length: ")

    while not length.isdigit():
        length=input("Invalid\nEnter a password length: ")

    password = get_random_alphanumeric_string(length)

    if 'accounts' in user_entries[username]:
        user_entries[username]['accounts'].update({account : password})
    else:
        user_entries[username]['accounts'] = {account : password}

    writeToDB(user_entries)
    pyperclip.copy(password)
    print("Password copied to clip...\n")



def deletePass(username):
    user_entries = getDB()

    while True:
        account = input("Enter the account you wish to delete: ")

        if(account in user_entries[username]['accounts'].keys()):
            del user_entries[username]['accounts'][account]

            writeToDB(user_entries)

            break

        else:
            print("Account does not exist...")

def deleteUser(username):
    user_entries = getDB()

    del user_entries[username]

    writeToDB(user_entries)

def getPass(username):
    user_entries = getDB()

    while True:
        account_to_get = input("Enter the account you want the password for: ")

        if(account_to_get in user_entries[username]['accounts'].keys()):
            pyperclip.copy(user_entries[username]['accounts'][account_to_get])
            print("Password copied to clip...\n")
            break

        else:
            print("Account does not exist...")
        

#HELPER FUNCTIONS
def writeToDB(user_entries):
    new_json = open("userDB.json", "w")
    json.dump(user_entries, new_json)
    new_json.close()

def getDB():
    if os.path.exists("userDB.json"):
        json_db_file = open("userDB.json", "r+")
    else:
        json_db_file = open("userDB.json", "w+")
    if os.stat("userDB.json").st_size == 0:
        user_entries = {}
    else:
        user_entries = json.load(json_db_file)
    json_db_file.close()
    return user_entries

def get_random_alphanumeric_string(length):
    letters_and_digits = string.ascii_letters + string.digits + '!@#$%^&*()'
    result_str = ''.join((random.choice(letters_and_digits) for i in range(int(length))))
    return result_str

mainMenu()