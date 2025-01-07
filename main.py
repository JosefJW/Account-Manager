import os
from dotenv import load_dotenv
import sqlite3
import re
import bcrypt
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class AccountManager():
    def __init__(self, db_path='users.db', smtp_server="smtp.gmail.com", smtp_port=587):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self.openConnection()
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port

        load_dotenv()

        if not os.path.exists('.env'):
            with open('.env', 'w') as file:
                file.write("""EMAIL_ADDRESS=your_email@example.com
                           EMAIL_PASSWORD=your_password""")

        email = os.getenv('EMAIL_ADDRESS')
        password = os.getenv('EMAIL_PASSWORD')

        if not email or not password or email == 'your_email@example.com' or password == 'your_password':
            print("You need to set up the email and password to send validation emails from. We recommend sending a test email with the send_email(subject, body, to_email) once after inputting your information.")
            self._get_credentials()

    def _get_credentials(self):
        email = input("Enter your email address: ")
        password = input("Enter your email password: ")

        os.environ['EMAIL_ADDRESS'] = email
        os.environ['EMAIL_PASSWORD'] = password

        with open('.env', 'w') as f:
            f.write(f"EMAIL_ADDRESS={email}\n")
            f.write(f"EMAIL_PASSWORD={password}\n")
        
        print("Credentials saved.")

    def openConnection(self):
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            email_validated INTEGER DEFAULT 0,
            username TEXT UNIQUE,
            password TEXT,
            token TEXT
        )
        ''')
        self.conn.commit()

    def closeConnection(self):
        self.conn.close()

    def _isValidEmail(self, email):
        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        return True if re.fullmatch(regex, email) else False

    def _isValidPassword(self, password):
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

    def _hashPassword(self, password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def checkPassword(self, username, password):
        self.cursor.execute('''
        SELECT password FROM users WHERE username = ?
        ''', (username,))

        hashed_password = self.cursor.fetchone()[0]

        if (bcrypt.checkpw(password.encode('utf-8'), hashed_password)):
            return True
        return False

    def insertUser(self, email, username, password):
        if not self._isValidEmail(email):
            return False
        if not self._isValidPassword(password):
            return False
        
        token = self._getUniqueToken()

        self.cursor.execute('''
        INSERT INTO users (email, username, password, token) VALUES (?, ?, ?, ?)
        ''', (email, username, self._hashPassword(password), token))
        self.conn.commit()
        return True

    def _getUniqueToken(self):
        token = secrets.token_urlsafe()
        count = 0
        while True:
            self.cursor.execute('''
            SELECT COUNT(*) FROM users WHERE token = ?
            ''', (token,))
            count = self.cursor.fetchone()[0]
            if count == 0:
                break
        return token

    def _validateEmail(self, token):
        if token == '':
            return False
        self.cursor.execute('''
        UPDATE users
        SET email_validated = 1, token = ?
        WHERE token = ?
        ''', ('', token,))
        self.conn.commit()
        return True

    def send_email(self, subject, body, to_email):
        load_dotenv()

        from_email = os.getenv('EMAIL_ADDRESS')
        password = os.getenv('EMAIL_PASSWORD')

        if not from_email or not password:
            raise ValueError("No email credentials")
        
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(from_email, password)
                server.sendmail(from_email, to_email, msg.as_string())
        except Exception as e:
            print(f"Error sending email: {e}")