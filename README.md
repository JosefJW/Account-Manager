Account Manager

Welcome to the Account Manager! This tool allows users to securely manage and store login credentials for various accounts. It ensures that login information is encrypted and easily accessible while providing a simple and efficient interface. Please note that this is purely educational and should not be used in any production environments.


Features (In Progress)

    User Authentication: Allows users to create an account and securely log in.
    Password Storage: Stores login credentials in an encrypted format to ensure security.
    Account Management: Users can add, update, and delete account credentials.
    Encryption: All passwords are securely encrypted using industry-standard algorithms.
    Password Retrieval: Retrieve stored login information with a secure process.
    Two-Factor Authentication: Allow users to have two-factor authentication

Technologies Used

    Backend: Python
    Frontend: HTML/CSS and JavaScript
    Database: SQLite
    Encryption: bcrypt, pyotp

Installation (Note that this is incomplete and will not currently function)

    Clone this repository.
    Install the required dependencies:

pip install -r requirements.txt

    Set up the database and environment variables:
        Create a .env file and add necessary configurations (if you run the program without one properly setup, it will ask you for the information it needs).
    Run the application:

python app.py 

Usage

    Upon starting the app, create a new user account by providing a username and password.
    You will receive an email to validate your account.
    After logging in, you can add, view, edit, and delete your account credentials in the dashboard.
    Passwords are encrypted in the database and will never be stored in plaintext.
    Log out when finished to ensure your account remains secure.

Future Features

    Multi-factor Authentication (MFA): Integrate additional layers of security for user login.
    Password Strength Checker: Suggest strong passwords during account creation.
    Password Recovery: Implement a process to recover forgotten passwords securely.

Contributing

Feel free to fork this repository and contribute by submitting pull requests. Here are a few ways you can help:

    Improve authentication flow.
    Enhance encryption or add more security features.
    Add additional account management functionality.
    Improve the user interface.

License

This project is open-source and available under the MIT License.
Contact

If you have any questions or suggestions, feel free to reach out:

    Email: josefwolf591@gmail.com
    GitHub: github.com/josefjw
