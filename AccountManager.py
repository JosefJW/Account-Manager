import os
import time
import uuid
from dotenv import load_dotenv
import sqlite3
import re
import bcrypt
import pyotp
import qrcode
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class AccountManager():
    def __init__(self, db_path='users.db', smtp_server="smtp.gmail.com", smtp_port=587, send_validation_email_callback=None, is_valid_password_callback=None):
        """
        Initialize the account manager

        
        Parameters:
        db_path (str): Path to store SQL database

        smtp_server (str): SMTP server to send emails with

        smtp_port (int): Port to send emails with

        send_validation_email_callback (function): Function to use when sending validation emails
        Default:
            def send_validation_email(self, validation_url, email):
                self.sendEmail("Validate Email", validation_url, email)

        is_valid_password_callback (function): Function to use when checking if a password is valid
        Default:
            def is_valid_password(self, password):
                errors = {'is_valid': True,
                  'short': False,
                  'no_lowercase': False,
                  'no_uppercase': False,
                  'no_num': False,
                  'no_special': False}
                if len(password) < 8: # Password should be at least 8 chars
                    errors['is_valid'] = False
                    errors['short'] = True
                if not re.search(r'[a-z]', password): # Password should have at least one lowercase char
                    errors['is_valid'] = False
                    errors['no_lowercase'] = True
                if not re.search(r'[A-Z]', password): # Password should have at least one uppercase char
                    errors['is_valid'] = False
                    errors['no_uppercase'] = True
                if not re.search(r'[0-9]', password): # Password should have at least one number
                    errors['is_valid'] = False
                    errors['no_num'] = True
                if not re.search(r'[!-\/:-@[-`{-~]', password): # Password should have at least one special char
                    errors['is_valid'] = False
                    errors['no_special'] = True
                return errors
        """

        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self.open_connection()
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port

        self.send_validation_email_callback = send_validation_email_callback or self.send_validation_email # If no other function is provided, use default functions
        self.is_valid_password_callback = is_valid_password_callback or self.is_valid_password

        load_dotenv() # Loads the .env file

        # Create a .env file if one does not exist
        if not os.path.exists('.env'):
            with open('.env', 'w') as file:
                file.write("""EMAIL_ADDRESS=your_email@example.com
                           EMAIL_PASSWORD=your_password
                           VALIDATION_URL=your_validation_url""")

        # Get info from the .env file
        email = os.getenv('EMAIL_ADDRESS')
        password = os.getenv('EMAIL_PASSWORD')
        validation_url = os.getenv('VALIDATION_URL')

        # Get correct info for .env file if it only has the default values
        if not email or not password or email == 'your_email@example.com' or password == 'your_password':
            print("You need to set up the email and password to send validation emails from. We recommend sending a test email with the send_email(subject, body, to_email) function once after inputting your information.")
            self.get_credentials()
        if not validation_url or validation_url == 'your_validation_url':
            self.get_validation_url()



    def get_validation_url(self):
        """
        Prompts the user for the validation URL that validation emails should direct to and adds that to the .env file.
        """

        email = os.getenv('EMAIL_ADDRESS')
        password = os.getenv("EMAIL_PASSWORD")
        validation_url = input("URL for validation emails to direct to: ")

        os.environ['VALIDATION_URL'] = validation_url

        with open('.env', 'w') as f:
            f.write(f"EMAIL_ADDRESS={email}\n")
            f.write(f"EMAIL_PASSWORD={password}\n")
            f.write(f"VALIDATION_URL={validation_url}\n")
        
        print("URL saved")



    def get_credentials(self):
        """
        Prompts the user for the email address and password to be used to send emails from and adds them to the .env file.
        """

        email = input("Enter your email address: ")
        password = input("Enter your email password: ")
        validation_url = os.getenv('VALIDATION_URL')

        os.environ['EMAIL_ADDRESS'] = email
        os.environ['EMAIL_PASSWORD'] = password

        with open('.env', 'w') as f:
            f.write(f"EMAIL_ADDRESS={email}\n")
            f.write(f"EMAIL_PASSWORD={password}\n")
            f.write(f"VALIDATION_URL={validation_url}\n")
        
        print("Credentials saved.")


    #TODO: user_login: locked, locked_expiration_time, password_reset_token, password_reset_token_expiration_time, last_password_change, user_status, last_ip, recovery_email, account_type
    #TODO: security_questions: uid, question/answer 1, 2, 3
    #TODO: audit_log: uid, action, timestamp
    #TODO: user_ips: uid, ip_address, timestamp
    #TODO: user_sessions: uid, session_token, ip_address, user_agent, created_at, last_activity
    def open_connection(self):
        """
        Opens the SQL connection.

        SQL user_login Table Fields: Handles all information needed for a user to login and change their login
            uid: Unique identifier for each user
            email: Unique email for a user
            email_validated: 1 if the user has validated their email address; 0 otherwise
            username: Unique username for a user
            password: The user's hashed password
            created_at: Time that the account was created at
            last_login: Time of last successful login
            failed_login_attempts: Number of failed login attempts
            locked: 1 if account is locked; 0 otherwise
            locked_expiration_time: Time when the account will be unlocked
            password_reset_token: Unique token for resetting the account password
            password_reset_token_expiration_time: Time when the password reset token will expire
            validation_token: Unique token for validating the account email
            validation_token_expiration_time: Time when the validation token will expire
            two_factor_enabled: 1 if two-factor authentication is enabled; 0 otherwise
            two_factor_secret: Secret code for two-factor authentication
            last_password_change: Time of last password change
            user_status: Status of the user (i.e. 'active', 'suspended', 'banned', etc.)
            last_ip: Last IP that the user logged in from
            recovery_email: Recovery email address
            account_type: Type of account (i.e. 'user', 'admin', 'developer', etc.)
        
        SQL security_questions Table Fields: Stores security questions and answers
            uid: User's unique id
            security_question_1: Security question 1
            security_answer_1: Hashed answer to security question 1
            security_question_2: Security question 2
            security_answer_2: Hashed answer to security question 2
            security_question_3: Security question 3
            security_answer_3: Hashed answer to security question 3

        SQL audit_log Table Fields: Stores all attempts at logging in
            id: Entry id
            uid: User's unique id
            action: Action taken (i.e. 'Successful Login', 'Failed Login', etc.)
            timestamp: Time of action

        SQL user_ips Table Fields: 
            id: Entry id
            uid: User's unique id
            ip_address: IP address of user login
            timestamp: Time of user login
        
        SQL user_sessions Table Fields:
            session_id: Unique session id
            uid: User's unique id
            session_token: Unique authenticated session token
            ip_address: IP address of current session
            user_agent: Browser or device used for login
            created_at: Time the session was started
            last_activity: Time of last activity in the session
        """

        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        
        # user_login
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_login (
            uid TEXT PRIMARY KEY UNIQUE,
            email TEXT UNIQUE,
            email_validated INTEGER DEFAULT 0,
            username TEXT UNIQUE,
            password TEXT,
            created_at INTEGER DEFAULT CURRENT_TIMESTAMP,
            last_login INTEGER,
            failed_login_attempts INTEGER DEFAULT 0,
            locked INTEGER DEFAULT 0,
            locked_timer INTEGER DEFAULT 0,
            password_reset_token TEXT,
            password_reset_token_expiration_time INTEGER,
            validation_token TEXT,
            validation_token_expiration_time INTEGER DEFAULT 0,
            two_factor_enabled INTEGER DEFAULT 0,
            two_factor_secret TEXT,
            last_password_change INTEGER,
            user_status TEXT DEFAULT 'active',
            last_ip TEXT,
            recovery_email TEXT,
            account_type TEXT DEFAULT 'user'
        )
        ''')
        
        # security_questions
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_questions (
            uid TEXT PRIMARY KEY,
            security_question_1 TEXT,
            security_answer_1 TEXT,
            security_question_2 TEXT,
            security_answer_2 TEXT,
            security_question_3 TEXT,
            security_answer_3 TEXT,
            FOREIGN KEY(uid) REFERENCES user_login(uid)
        )
        ''')
        
        # audit_log
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT,
            action TEXT,
            timestamp INTEGER DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(uid) REFERENCES user_login(uid)
        )
        ''')
        
        # user_ips
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT,
            ip_address TEXT,
            timestamp INTEGER DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(uid) REFERENCES user_login(uid)
        )
        ''')
        
        # user_sessions
        self.cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            session_id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid TEXT,
            session_token TEXT UNIQUE,
            ip_address TEXT,
            user_agent TEXT,
            created_at INTEGER DEFAULT CURRENT_TIMESTAMP,
            last_activity INTEGER DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(uid) REFERENCES user_login(uid)
        );
        ''')
        
        self.conn.commit()



    def close_connection(self):
        """
        Closes the SQL connection
        """

        self.conn.close()



    def generate_unique_uid(self):
        """
        Generates a unique user id

        Returns:
            string: The unique user id
        """
        uid = None
        while True:
            uid = str(uuid.uuid4())
            self.cursor.execute('''
            SELECT COUNT(*) FROM user_login WHERE validation_token = ?
            ''', (uid, ))
            count = self.cursor.fetchone()[0]
            if count == 0:
                break # Only break if no other user has the same token
        return uid



    def is_valid_email(self, email):
        """
        Checks if a string is a valid email address.

        Parameters:
        email (str): String to check if it is a valid email

        Returns:
        bool: True if it is a valid email; False otherwise
        """

        regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        return True if re.fullmatch(regex, email) else False



    def is_valid_password(self, password):
        """
        Checks if a string meets password criteria (at least 8 chars long, )

        Parameters:
        password (str): String to check if it is a valid password

        Returns:
        dict:
            is_valid: True if the password is valid; False otherwise
            short: True if the password is too short; False otherwise
            no_lowercase: True if the password has no lowercase chars; False otherwise
            no_uppercase: True if the password has no uppercase chars; False otherwise
            no_num: True if the password has no numbers; False otherwise
            no_special: True if the password has no special chars; False otherwise
        """

        errors = {'is_valid': True,
                  'short': False,
                  'no_lowercase': False,
                  'no_uppercase': False,
                  'no_num': False,
                  'no_special': False}

        if len(password) < 8: # Password should be at least 8 chars
            errors['is_valid'] = False
            errors['short'] = True
        if not re.search(r'[a-z]', password): # Password should have at least one lowercase char
            errors['is_valid'] = False
            errors['no_lowercase'] = True
        if not re.search(r'[A-Z]', password): # Password should have at least one uppercase char
            errors['is_valid'] = False
            errors['no_uppercase'] = True
        if not re.search(r'[0-9]', password): # Password should have at least one number
            errors['is_valid'] = False
            errors['no_num'] = True
        if not re.search(r'[!-\/:-@[-`{-~]', password): # Password should have at least one special char
            errors['is_valid'] = False
            errors['no_special'] = True
        return errors



    def hash_password(self, password):
        """
        Hashes a password

        Parameters:
        password (str): Password to be hashed

        Returns:
        bytes: The hashed password
        """

        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())



    def login(self, username, password):
        self.cursor.execute('''
        SELECT uid FROM user_login WHERE username = ?
        ''', (username,))
        uid = self.cursor.fetchone()[0]
        if not uid:
            return False
        if self.check_password(username, password):
            return
            # Set last_login time
            self.cursor.execute('''
            UPDATE user_login
            SET last_login = >
            WHERE username = ?
            ''', (int(time.time()), username,))
            self.conn.commit()
        else:
            # Enter into audit_log
            self.cursor.execute('''
            INSERT INTO audit_log (uid, action, timestamp) VALUES (?, ?, ?)
            ''', (uid, "Incorrect Password", int(time.time())))
            
            # Update failed_login_attempts
            self.cursor.execute('''
            UPDATE user_login
            SET failed_login_attempts = failed_login_attempts + 1
            WHERE username = ?
            ''', (username,))
            self.conn.commit()



    def check_password(self, username, password):
        """
        Checks if a password is correct for a given username

        Parameters:
        username: Username to check password for
        password: Password to check if it is correctly associated with username

        Returns:
        bool: True if password is the correct password; False otherwise
        """

        # Get the hashed password associated with username
        self.cursor.execute('''
        SELECT password FROM user_login WHERE username = ?
        ''', (username,))
        hashed_password = self.cursor.fetchone()[0]

        # Check if password matches the hashed password
        if (bcrypt.checkpw(password.encode('utf-8'), hashed_password)):
            return True
        return False



    def insert_user(self, email, username, password):
        """
        Makes sure inputs are valid, adds a user to the database, and sends a validation email

        Parameters:
        email: Email associated with the user
        username: Username associated with the user
        password: Password associated with the user

        Returns:
        tuple:
            bool: True is user was successfully inserted; False otherwise
            dict: 
        """

        errors = {
            'email': {'is_valid': self.is_valid_email(email)},
            'password': self.is_valid_password_callback(password),
        }
        if not (errors['email']['is_valid'] and errors['password']['is_valid']):
            return (False, errors)
        
        # Create a unique token for validating the email address
        validation_token, validation_token_expiration_time = self.get_unique_token()
        uid = self.generate_unique_uid()

        # Add the user to the database
        self.cursor.execute('''
        INSERT INTO user_login (uid, email, username, password, validation_token, validation_token_expiration_time, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (uid, email, username, self.hash_password(password), validation_token, validation_token_expiration_time, int(time.time())))
        self.conn.commit()

        # Send the validation email
        validation_url = os.getenv('VALIDATION_URL')
        validation_url += "?token="+str(validation_token)
        self.send_validation_email_callback(validation_url, email)

        return (True, None)



    def send_validation_email(self, validation_url, email):
        """
        Sends validation emails for new users

        Parameters:
        validation_url: URL that user should press to validate their email
        email: Email to send validation to
        """

        self.send_email("Validate Email", validation_url, email)



    def get_unique_token(self):
        """
        Provides a unique token for validation and an expiration time for the token

        Returns:
        str: Unique token
        int: Expiration time for the token
        """

        token = secrets.token_urlsafe()
        count = 0
        while True: # Continuously loop until a unique token is found
            self.cursor.execute('''
            SELECT COUNT(*) FROM user_login WHERE validation_token = ? OR password_reset_token = ?
            ''', (token, token,))
            count = self.cursor.fetchone()[0]
            if count == 0:
                break # Only break if no other user has the same token
        expiration_time = int(time.time()) + 3600  # 3600 seconds = 1 hour
        return token, expiration_time



    def is_token_not_expired(self, token):
        """
        Checks that a token has not expired

        Parameters:
        token: Token to check expiration of
        """

        # Check for email validation token
        self.cursor.execute('''
        SELECT validation_token_expiration_time FROM user_login WHERE validation_token = ?
        ''', (token,))
        row = self.cursor.fetchone()

        if row:
            expiration_time = row[0]
            if int(time.time()) < expiration_time:  # Token is still valid
                return True
            else:  # Token has expired
                self.invalidate_token(token)
                return False
        

        # Check for password reset token
        self.cursor.execute('''
        SELECT password_reset_token_expiration_time FROM user_login WHERE password_reset_token = ?
        ''', (token,))
        row = self.cursor.fetchone()

        if row:
            expiration_time = row[0]
            if int(time.time()) < expiration_time: # Token is still valid
                return True
            else: # Token is expired
                self.invalidate_token(token)
                return False
        
        return False # Token not found



    def invalidate_token(self, token):
        """
        Sets a given token to the empty string and expiration time to 0

        Parameters:
        token: The token to invalidate
        """

        self.cursor.execute('''
        UPDATE user_login
        SET validation_token = '', validation_token_expiration_time = 0
        WHERE validation_token = ?
        ''', (token,))
        self.conn.commit()

        self.cursor.execute('''
        UPDATE user_login
        SET password_reset_token = '', password_reset_token_expiration_time = 0
        WHERE password_reset_token = ?
        ''', (token,))



    def validate_email(self, token):
        """
        Validates the user's email.

        Returns:
        bool: True if validation is successful; False otherwise
        """

        if token == '': # No token
            return False

        if not self.is_token_not_expired(token):
            return False

        self.cursor.execute('''
        UPDATE user_login
        SET email_validated = 1, validation_token = ?
        WHERE validation_token = ?
        ''', ('', token,))
        self.conn.commit()

        if self.cursor.rowcount == 0: # No rows updated
            return False
        self.invalidate_token(token)
        return True



    def send_email(self, subject, body, to_email):
        """
        Sends an email from the email stored in .env

        Parameters:
        subject: Subject of the email
        body: Body of the email
        to_email: Email to send to

        Returns:
        bool: True if email was sent successfully; False otherwise
        """

        # Get the sender email information from the .env file
        load_dotenv()
        from_email = os.getenv('EMAIL_ADDRESS')
        password = os.getenv('EMAIL_PASSWORD')
        if not from_email or not password:
            raise ValueError("No email credentials")
        
        # Create the email
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Login and send the email
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(from_email, password)
                server.sendmail(from_email, to_email, msg.as_string())
            return True
        except Exception as e:
            return False

    def generate_2fa_secret(self, uid):
        secret = pyotp.random_base32()
        self.cursor.execute('''
        UPDATE user_login
        SET two_factor_secret = ?
        WHERE uid = ?
        ''', (secret, uid))
        self.conn.commit()
        return secret
    
    def get_2fa_qr_code(self, email, secret):
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=email, issuer_name="App")
        qr = qrcode.make(uri)
        qr.save(f"{email}_2fa.png")
        
    def validate_otp(self, uid, otp):
        self.cursor.execute('''
        SELECT two_factor_secret FROM user_login WHERE uid = ?
        ''', (uid,))
        secret = self.cursor.fetchone()[0]
        if not secret:
            raise ValueError("2FA not enabled for this user.")
        
        totp = pyotp.TOTP(secret)
        return totp.verify(otp)
    
    def enable_2fa(self, uid):
        secret = self.generate_2fa_secret(uid)
        return secret
    
    def disable_2fa(self, uid):
        self.cursor.execute('''
        UPDATE user_login SET two_factor_enabled = 0 two_factor_secret = NULL WHERE uid = ?
        ''', (uid,))
        self.conn.commit()

manager = AccountManager()
#manager.insert_user("BobbyMcGee@gmail.com", "BobbyMcGee", "BobbyMcGee#1")
#manager.login("BobbyMcGee", "BobbyMcGee#2")

