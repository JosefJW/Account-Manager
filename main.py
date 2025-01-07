import sqlite3
import re
import bcrypt

conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    username TEXT UNIQUE,
    password TEXT
)
''')
conn.commit()

"""
cursor.execute('''
INSERT INTO users (email, username, password) VALUES (?, ?, ?)
''', ('josewof591@gmal.com', 'se', 'password'))
conn.commit()
"""

def isValidEmail(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
    return True if re.fullmatch(regex, email) else False

def isValidPassword(password):
    if len(password) < 8:
        print("Not long enough")
        return False
    if not re.search(r'[a-z]', password):
        print("No lowercase")
        return False
    if not re.search(r'[A-Z]', password):
        print("No uppercase")
        return False
    if not re.search(r'[0-9]', password):
        print("No number")
        return False
    if not re.search(r'[!-\/:-@[-`{-~]', password):
        print("No special char")
        return False
    return True

def hashPassword(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def checkPassword(username, password):
    cursor.execute('''
    SELECT password FROM users WHERE username = ?
    ''', (username,))

    hashed_password = cursor.fetchone()[0]

    if (bcrypt.checkpw(password.encode('utf-8'), hashed_password)):
        return True
    return False

def insertUser(email, username, password):
    if not isValidEmail(email):
        return False
    if not isValidPassword(password):
        return False
    
    cursor.execute('''
    INSERT INTO users (email, username, password) VALUES (?, ?, ?)
    ''', (email, username, hashPassword(password)))
    conn.commit()
    return True

