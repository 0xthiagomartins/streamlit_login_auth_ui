import re
import json
try:
    from trycourier import Courier
except ImportError:
    from courier.client import Courier
import secrets
from argon2 import PasswordHasher
import requests

ph = PasswordHasher()

def check_usr_pass(username: str, password: str) -> bool:
    """
    Authenticates the username and password.
    """
    with open("_secret_auth_.json", "r") as auth_json:
        authorized_user_data = json.load(auth_json)

    for registered_user in authorized_user_data:
        if registered_user['username'] == username:
            try:
                passwd_verification_bool = ph.verify(registered_user['password'], password)
                if passwd_verification_bool:
                    return True
            except:
                pass
    return False


def load_lottieurl(url: str) -> str:
    """
    Fetches the lottie animation using the URL.
    """
    try:
        r = requests.get(url)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        return None


def check_valid_name(name_sign_up: str) -> bool:
    """
    Checks if the user entered a valid name while creating the account.
    """
    name_regex = r'^[A-Za-z_][A-Za-z0-9_]*'

    return bool(re.search(name_regex, name_sign_up))


def check_valid_email(email_sign_up: str) -> bool:
    """
    Checks if the user entered a valid email while creating the account.
    """
    regex = re.compile(
        r'([A-Za-z0-9]+[._-])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Za-z]{2,})+'
    )

    return bool(re.fullmatch(regex, email_sign_up))


def check_unique_email(email_sign_up: str) -> bool:
    """
    Checks if the email already exists (since email needs to be unique).
    """
    with open("_secret_auth_.json", "r") as auth_json:
        authorized_users = json.load(auth_json)

    existing_emails = [user['email'] for user in authorized_users]
    return email_sign_up not in existing_emails


def non_empty_str_check(username_sign_up: str) -> bool:
    """
    Checks for non-empty strings.
    """
    if not username_sign_up.strip():
        return False
    return True


def check_unique_usr(username_sign_up: str) -> bool:
    """
    Checks if the username already exists (since username needs to be unique),
    also checks for non-empty username.
    """
    with open("_secret_auth_.json", "r") as auth_json:
        authorized_users = json.load(auth_json)

    existing_usernames = [user['username'] for user in authorized_users]
    if username_sign_up in existing_usernames:
        return False
    return non_empty_str_check(username_sign_up)


def register_new_usr(name_sign_up: str, email_sign_up: str, username_sign_up: str, password_sign_up: str) -> None:
    """
    Saves the information of the new user in the _secret_auth.json file.
    """
    new_usr_data = {
        'username': username_sign_up,
        'name': name_sign_up,
        'email': email_sign_up,
        'password': ph.hash(password_sign_up)
    }

    with open("_secret_auth_.json", "r+") as auth_json:
        authorized_users = json.load(auth_json)
        authorized_users.append(new_usr_data)
        auth_json.seek(0)
        json.dump(authorized_users, auth_json)
        auth_json.truncate()


def check_username_exists(user_name: str) -> bool:
    """
    Checks if the username exists in the _secret_auth.json file.
    """
    with open("_secret_auth_.json", "r") as auth_json:
        authorized_users = json.load(auth_json)

    return any(user['username'] == user_name for user in authorized_users)


def check_email_exists(email_forgot_passwd: str) -> (bool, str):
    """
    Checks if the email entered is present in the _secret_auth_.json file.
    """
    with open("_secret_auth_.json", "r") as auth_json:
        authorized_users = json.load(auth_json)

    for user in authorized_users:
        if user['email'] == email_forgot_passwd:
            return True, user['username']
    return False, None


def generate_random_passwd() -> str:
    """
    Generates a random password to be sent in email.
    """
    return secrets.token_urlsafe(10)


def send_passwd_in_email(auth_token: str, username_forgot_passwd: str, email_forgot_passwd: str, company_name: str, random_password: str) -> None:
    """
    Triggers an email to the user containing the randomly generated password.
    """
    client = Courier(auth_token=auth_token)
    client.send_message(
        message={
            "to": {"email": email_forgot_passwd},
            "content": {
                "title": f"{company_name}: Login Password!",
                "body": (
                    f"Hi {username_forgot_passwd},\n\n"
                    f"Your temporary login password is: {random_password}\n\n"
                    "{{info}}"
                )
            },
            "data": {"info": "Please reset your password at the earliest for security reasons."}
        }
    )


def change_passwd(email_: str, random_password: str) -> None:
    """
    Replaces the old password with the newly generated password.
    """
    with open("_secret_auth_.json", "r+") as auth_json:
        authorized_users = json.load(auth_json)
        for user in authorized_users:
            if user['email'] == email_:
                user['password'] = ph.hash(random_password)
        auth_json.seek(0)
        json.dump(authorized_users, auth_json)
        auth_json.truncate()


def check_current_passwd(email_reset_passwd: str, current_passwd: str) -> bool:
    """
    Authenticates the password entered against the username when
    resetting the password.
    """
    with open("_secret_auth_.json", "r") as auth_json:
        authorized_users = json.load(auth_json)

    for user in authorized_users:
        if user['email'] == email_reset_passwd:
            try:
                return ph.verify(user['password'], current_passwd)
            except:
                return False
    return False

# Author: Gauri Prabhakar
# GitHub: https://github.com/GauriSP10/streamlit_login_auth_ui
