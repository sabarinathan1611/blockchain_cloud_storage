import sqlite3
from faker import Faker
import random
from datetime import datetime
from function import makedir
import secrets
from dataencryption import *
aes_cipher = AESCipher()


# Create an instance of Faker
fake = Faker()

# Connect to the SQLite database
conn = sqlite3.connect('d.db')
cursor = conn.cursor()

# Create the DeleteAccount table (if it doesn't already exist)
cursor.execute('''
CREATE TABLE IF NOT EXISTS DeleteAccount (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    email TEXT NOT NULL,
    deleted BOOLEAN DEFAULT 0
)
''')

# Create the User table (if it doesn't already exist)
cursor.execute('''
CREATE TABLE IF NOT EXISTS User (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    date DATETIME DEFAULT CURRENT_TIMESTAMP,
    role TEXT DEFAULT 'user',
    path TEXT UNIQUE NOT NULL,
    is_verified BOOLEAN DEFAULT 0,
    verification_token TEXT DEFAULT '',
    used_storage INTEGER DEFAULT 0,
    limited_storage INTEGER DEFAULT 209715200
)
''')

# Function to insert random data into the tables
def insert_random_data(num_records):
    delete_account_data = []
    user_data = []
    emaillist=[]

    for _ in range(num_records):
        # Generate data for User table
        username =  aes_cipher.encrypt_data(f'username_{_}')
        print(len(user_data))

	#print('User DATA',len(user_data))
        email = aes_cipher.encrypt_data(f'test@test{len(user_data)}.com')
        


        password = 'scrypt:32768:8:1$oAb9BSkgXE3mgQLh$a8636f1d8cd07032139eda320e4993485493b2ac0c6f8740f5f04987562c73403f41176695961bcbf5108828d1acdb0a92b8cdcc55344061b4771f9f2770a43f'
        date = fake.date_time_this_decade()
        path = aes_cipher.encrypt_data(makedir())
        is_verified = True
        verification_token = aes_cipher.encrypt_data(secrets.token_urlsafe())
        used_storage = random.randint(0, 209715200)
        limited_storage = 209715200

        user_data.append((username, email, password, date, 'user', path, is_verified, verification_token, used_storage, limited_storage))

        # Generate data for DeleteAccount table
        user_id = _  # Assuming the user_id is a sequential integer starting from 0
        #email = aes_cipher.encrypt_data(f'test@test{len(user_data)}.com')
        #print(f'test@test{len(user_data)}.com')
        deleted = fake.boolean()

        delete_account_data.append((user_id, email, deleted))


    # Insert data into User table
    cursor.executemany('''
    INSERT INTO User (username, email, password, date, role, path, is_verified, verification_token, used_storage, limited_storage)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', user_data)

    # Insert data into DeleteAccount table
    cursor.executemany('''
    INSERT INTO DeleteAccount (user_id, email, deleted)
    VALUES (?, ?, ?)
    ''', delete_account_data)

    # Commit the transaction
    conn.commit()

# Insert 1,000,000 records into each table
insert_random_data(1000000)

# Close the connection
conn.close()

with open('email.txt', 'w') as file:
    # Iterate over the list and write each item to the file
    for email in emaillist:
        file.write(f"{email}\n")
