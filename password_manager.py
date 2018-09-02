#!/usr/bin/python
import sys
import re
import getpass
import os
import subprocess
import platform
import readline
import itertools
import shlex

import xml.etree.ElementTree as ET


# TODO
# - To use pyperclip???
# - Commands with parameters
# - Consider these libraries:
#       https://github.com/italorossi/ishell
#       https://github.com/jonathanslenders/python-prompt-toolkit
# Print and ask copy to clipboard
# Class Account


try:
    from pretty_bad_protocol import gnupg
except ImportError:
    print("[x] ERROR: Cannot find 'pretty_bad_protocol'. Please install it: pip install pretty_bad_protocol")
    sys.exit()


WHICH_CMD = 'which'
CLIPBOARD_ENCODING = 'utf-8'


def _executable_exists(name):
    return subprocess.call([WHICH_CMD, name],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0



class PasswordManagerException(Exception):
    def __init__(self, msg=None):
        self._msg = msg

    def __str__(self):
        if self._msg:
            return self._msg
        else:
            return self.__doc__


class AccountNotFoundException(PasswordManagerException):
    """Account not found"""


class AccountExistsException(PasswordManagerException):
    """Account name already exits"""


class EncryptionException(PasswordManagerException):
    """Cannot encrypt data!"""


class DecryptionException(PasswordManagerException):
    """Cannot decrypt data!"""



class XClip(object):
    DEFAULT_SELECTION='c'
    PRIMARY_SELECTION='p'

    @classmethod
    def copy(cls, text, primary=False):
        if primary:
            selection=cls.PRIMARY_SELECTION
        else:
            selection=cls.DEFAULT_SELECTION

        p = subprocess.Popen(['xclip', '-selection', selection],
                             stdin=subprocess.PIPE, close_fds=True)
        p.communicate(input=text.encode(CLIPBOARD_ENCODING))

    @classmethod
    def paste(cls, primary=False):
        if primary:
            selection=cls.PRIMARY_SELECTION
        else:
            selection=cls.DEFAULT_SELECTION

        p = subprocess.Popen(['xclip', '-selection', selection, '-o'],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             close_fds=True)
        stdout, stderr = p.communicate()
        # Intentionally ignore extraneous output on stderr when clipboard is empty
        return stdout.decode(CLIPBOARD_ENCODING)


class XSel(object):
    DEFAULT_SELECTION='-b'
    PRIMARY_SELECTION='-p'

    @classmethod
    def copy(cls, text, primary=False):
        if primary:
            selection_flag=cls.PRIMARY_SELECTION
        else:
            selection_flag=cls.DEFAULT_SELECTION

        p = subprocess.Popen(['xsel', selection_flag, '-i'],
                             stdin=subprocess.PIPE, close_fds=True)
        p.communicate(input=text.encode(CLIPBOARD_ENCODING))

    @classmethod
    def paste(cls, primary=False):
        if primary:
            selection_flag=cls.PRIMARY_SELECTION
        else:
            selection_flag=cls.DEFAULT_SELECTION

        p = subprocess.Popen(['xsel', selection_flag, '-o'],
                             stdout=subprocess.PIPE, close_fds=True)
        stdout, stderr = p.communicate()
        return stdout.decode(CLIPBOARD_ENCODING)


if _executable_exists("xclip"):
    clipboard = XClip
elif _executable_exists("xsel"):
    clipboard = XSel


def clear_screen():
    os.system('reset')



def warn_print(s):
    print("[!] WARNINIG: {0}".format(s))

def error_print(s):
    print("[x] ERROR: {0}".format(s))

def info_print(s):
    print("[*] {0}".format(s))


def print_with_indent(text, indent="  "):
    print("\n".join(indent+ l for l in text.splitlines()))


def decrypt_file(gpg, filename, password):
    with open(filename, "rb") as f:
        dec_data = gpg.decrypt(f.read(), passphrase=password)

    if dec_data.ok is False:
        raise DecryptionException(dec_data.stderr)

    return dec_data.data.decode("utf-8")



def encrypt_file(gpg, filename, password, data):
    data = data.encode("utf-8")

    enc_d = gpg.encrypt(data, symmetric='AES256', passphrase=password, armor=False, encrypt=False)

    if enc_d.ok is False:
        raise EncryptionException(enc_d.stderr)

    encrypted_data = enc_d.data


    with open(filename,'wb') as f:
        f.write(encrypted_data)

    return True


class Password_Manager(object):

    TITLE ="Password Manager"

    def __init__(self, filename):
        self._filename = filename
        self._master_password = None

        self._root = None

        self._show_passwords = False

        self._gpg = gnupg.GPG()


    def print_account(self, account, indent="  ", show_password=False):
        extra_info = None
        passwd = None

        name = account.get('name').encode(sys.stdout.encoding)
        if account.find('extra_info') is not None and account.find('extra_info').text is not None:
            extra_info = account.find('extra_info').text.encode(sys.stdout.encoding)

        if show_password and account.find('password') is not None and account.find('password').text is not None:
            passwd = account.find('password').text.encode(sys.stdout.encoding)


        print("")
        print_with_indent("ACCOUNT NAME: {0}".format(name), indent=indent)

        if passwd is not None:
            print_with_indent("PASSWORD: {0}".format(passwd), indent=indent)

        if extra_info is not None:
            print_with_indent("EXTRA INFO: ", indent=indent)
            print_with_indent(extra_info, indent=indent+ "    ")

        print_with_indent("-"*40, indent=indent)


    def normalize_account_name(self, account_name):
        account_name = " ".join(account_name.lower().strip().split())
        account_name = account_name.replace("*", "")
        account_name = account_name.replace("?", "")

        return account_name


    def get_accounts(self):
        return self._root.findall('account')


    def save_accounts(self):
        data = ET.tostring(self._root)

        return encrypt_file(self._gpg, self._filename, self._master_password, data)


    def ask_password(self, old_password=None):
        while True:
            if old_password is None or old_password == "":
                new_password = getpass.getpass("Password: ")
            else:
                new_password = getpass.getpass("Password [{0}]: ".format(old_password))

            if new_password == "": return

            new_password = new_password.decode(sys.stdin.encoding)

            repeat_password = getpass.getpass("Repeat password: ")

            if new_password == repeat_password:
                return new_password
            else:
                warn_print("Passwords don't coincide")


    def create_account(self, account_name, old_password="", old_extra_info=""):
        account_name = self.normalize_account_name(account_name)

        new_account = ET.Element("account", {'name': account_name})

        new_password = self.ask_password(old_password)

        if new_password is None:
            new_password = old_password

        passwd = ET.SubElement(new_account, "password")
        passwd.text = new_password

        if old_extra_info:
            print("Extra info [{0}]: ".format(old_extra_info))
        else:
            print("Extra info: ")

        text_lines = []

        white_line = False
        while True:
            line = raw_input()
            if line:
                text_lines.append(line)
                white_line = False
            else:
                if white_line:
                    break
                else:
                    white_line = True


        text = '\n'.join(text_lines)
        text = text.strip().decode(sys.stdin.encoding)


        if not text:
            text = old_extra_info

        extra_info = ET.SubElement(new_account, "extra_info")
        extra_info.text = text

        return new_account


    def find_account(self, pattern):
        try:
            index = int(pattern)
        except ValueError:
            pass
        else:
            list_of_accounts = self.get_accounts()
            if 0 <= index < len(list_of_accounts):
                return list_of_accounts[index]


        if "*" in pattern or "?" in pattern:
            pattern = pattern.strip()
            pattern = re.sub(r"\*+", "*", pattern)
            pattern = re.sub(r"\s+\*\s+\*\s+", " * ", pattern)
            pattern = re.sub(r"^\*\s+\*\s+", "* ", pattern)
            pattern = re.sub(r"\s+\*\s+\*$", " *", pattern)

            _pattern = ""

            start = 0
            for match in re.finditer("[*?]", pattern):
                _pattern += re.escape(pattern[start: match.start()])

                wildcard = match.group()

                if wildcard == "*":
                    _pattern += ".+"
                elif wildcard == "?":
                    _pattern += ".?"

                start = match.end()

            _pattern += re.escape(pattern[start:])
            pattern = _pattern

            for account in self._root.findall('account'):
                if re.search(pattern, account.get('name'), flags=re.I):
                    return account

        else:
            pattern = self.normalize_account_name(pattern)

            for account in self._root.findall('account'):
                if pattern == account.get('name'):
                    return account

            for account in self._root.findall('account'):
                if pattern in account.get('name'):
                    return account


    def add_account(self, account_name):
        for account in self._root.findall('account'):
            if account_name == account.get('name'):
                raise AccountExistsException

        account = self.create_account(account_name)
        self._root.append(account)

        self.save_accounts()


    def command_list(self):
        """List all available account by name"""

        list_of_accounts = self.get_accounts()

        if list_of_accounts:
            print_with_indent("List of account:")
            for account_index, account in enumerate(list_of_accounts):
                print_with_indent("%d. "%account_index + account.get('name'))

        else:
            warn_print("No account")
    command_list.name = ["list", "l"]


    def command_add(self, account_name=None):
        """Add account"""

        if account_name is None:
            account_name = raw_input("Account name: ")
            account_name = account_name.strip()

            if account_name == "": return

        self.add_account(account_name)
        info_print("Account added!")
    command_add.name = ["add", "a"]


    def command_delete(self, account_pattern=None):
        """Delete account"""

        if account_pattern is None:
            account_pattern = raw_input("Write an account pattern: ")
            account_pattern = account_pattern.strip()

            if account_pattern == "": return

        account = self.find_account(account_pattern)

        if account is None:
            raise AccountNotFoundException
        else:
            print("are you sure that you want to delete this account? Answer 'y' to confirm.")
            self.print_account(account, show_password=self._show_passwords)

            answer = raw_input()
            answer = answer.strip()

            if answer == "y" or answer == "yes":
                self._root.remove(account)

                self.save_accounts()
                info_print("Account deleted!")
    command_delete.name = ["delete", "d"]


    def command_clipboard(self, account_pattern=None):
        """Copy password to clipboard"""

        if account_pattern is None:
            account_pattern = raw_input("Write an account pattern: ")
            account_pattern = account_pattern.strip()

            if account_pattern == "": return

        account = self.find_account(account_pattern)

        if account is None:
            raise AccountNotFoundException
        else:
            password = account.find('password').text
            clipboard.copy(password)

        info_print("Password copied to clipboard!")
    command_clipboard.name = ["clipboard", "c"]


    def command_modify(self, account_pattern=None):
        """Modify account"""

        if account_pattern is None:
            account_pattern = raw_input("Write an account pattern: ")
            account_pattern = account_pattern.strip()

            if account_pattern == "": return

        account = self.find_account(account_pattern)

        if account is None:
            raise AccountNotFoundException
        else:
            old_password = account.find('password').text
            old_extra_info = account.find('extra_info').text

            new_account = self.create_account(account.get('name'), old_password, old_extra_info)

            self._root.remove(account)
            self._root.append(new_account)

            self.save_accounts()

            info_print("Account successfully modified!")
    command_modify.name = ["modify"]


    def command_rename(self, account_name=None):
        """Rename account"""

        if account_name is None:
            account_name = raw_input("Account name: ")
            account_name = account_name.strip()

            if account_name == "": return


        for account in self._root.findall('account'):
            if account.get('name') == account_name:
                new_account_name = raw_input("New name for account: ")
                new_account_name = self.normalize_account_name(new_account_name)

                account.set("name", new_account_name)
                self.save_accounts()

                info_print("Account successfully renamed!")
                return

        raise AccountNotFoundException
    command_rename.name = ["rename"]


    def command_search(self, account_pattern=None):
        """Search account"""

        if account_pattern is None:
            account_pattern = raw_input("Write an account pattern: ")
            account_pattern = account_pattern.strip()

            if account_pattern == "": return


        account = self.find_account(pattern)
        if account is None:
            raise AccountNotFoundException
        else:
            self.print_account(account, show_password= self._show_passwords)
    command_search.name = ["search", "s"]


    def command_print_and_copy_to_cliboard(self, account_pattern=None):
        """Print account and copy password to clipboard"""

        if account_pattern is None:
            account_pattern = raw_input("Write an account pattern: ")
            account_pattern = account_pattern.strip()

            if account_pattern == "": return

        account = self.find_account(account_pattern)

        if account is None:
            raise AccountNotFoundException
        else:
            password = account.find('password').text
            clipboard.copy(password)

            print("\nPassword saved to clipboard.")
            self.print_account(account, show_password=self._show_passwords)
    command_print_and_copy_to_cliboard.name = ["pc"]


    def command_print_account_all(self, account_pattern=None):
        """Print all data of account (including the password)"""

        if account_pattern is None:
            account_pattern = raw_input("Write an account pattern: ")
            account_pattern = account_pattern.strip()

            if account_pattern == "": return

        account = self.find_account(account_pattern)

        if account is None:
            raise AccountNotFoundException
        else:
            print("\nPassword saved to clipboard.")
            self.print_account(account, show_password=True)
    command_print_account_all.name = ["print_all", "pa"]


    def command_print(self, account_pattern=None):
        """Print account"""

        if account_pattern is None:
            account_pattern = raw_input("Write an account pattern: ")
            account_pattern = account_pattern.strip()

            if account_pattern == "": return

        account = self.find_account(account_pattern)

        if account is None:
            raise AccountNotFoundException
        else:
            self.print_account(account, show_password=self._show_passwords)
    command_print.name = ["print", "p"]


    def command_all(self):
        """Print all accounts"""

        list_of_accounts = self.get_accounts()

        if list_of_accounts:
            print_with_indent("List of accounts")
            for account in list_of_accounts:
                self.print_account(account, show_password=self._show_passwords)
        else:
            warn_print("No account")
    command_all.name = ["all"]


    def command_show_passwords(self):
        """Show passwords"""

        self._show_passwords = True
        print("All password will be shown now!")
    command_show_passwords.name = ["show_passwords"]


    def command_hide_passwords(self):
        """Hide passwords"""

        self._show_passwords = False

        print("All password will be hidden now!")
    command_hide_passwords.name = ["hide_passwords"]


    def command_dump(self):
        """Dump file content in plain text"""
        ET.dump(root)
    command_dump.name = ["dump"]


    def command_help(self):
        """Print help"""
        print(self.HELP_MESSAGE)
    command_help.name = ["help", "h"]


    def command_clear(self):
        """Clear screen"""

        clear_screen()
        print(self.HELP_MESSAGE)
    command_clear.name = ["clear"]


    def command_exit(self):
        """Exit"""

        exit()
    command_exit.name = ["exit"]


    def run(self):
        if os.path.isfile(self._filename):
            new_file = False
        else:
            warn_print("A new password file will be created.")
            new_file = True

        try:
            self._master_password = getpass.getpass("Write the master password.\n")
        except KeyboardInterrupt:
            sys.exit()

        if new_file:
            try:
                repeated_master_password = getpass.getpass("Repeat password.\n")
            except KeyboardInterrupt:
                sys.exit()

            if self._master_password != repeated_master_password:
                error_print("Passwords doesn't coincide")
                sys.exit()

            self._root = ET.Element('accounts')

            self.save_accounts()
        else:
            try:
                data = decrypt_file(self._gpg, self._filename, self._master_password)
            except DecryptionException as e:
                error_print("Error doing decryption:\n%s"%str(e))
                sys.ext()


            self._root = ET.ElementTree(ET.fromstring(data.encode('utf-8'))).getroot()

        clear_screen()

        header = "-"*len(self.TITLE) + "\n" + self.TITLE + "\n" + "-"*len(self.TITLE) + "\n"
        print(header)


        print(self.HELP_MESSAGE)

        list_of_accounts = self.get_accounts()

        if list_of_accounts:
            print("List of accounts:")
            for account_index, account in enumerate(list_of_accounts):
                print("%d. "%account_index + account.get('name'))

        while True:
            try:
                user_input = raw_input("\nCommand: ")
            except KeyboardInterrupt:
                sys.exit()

            print("")

            command = shlex.split(user_input)
            command_name = command[0]

            if command_name in self.LIST_OF_COMMANDS:
                command_function = getattr(self, self.LIST_OF_COMMANDS[command_name])
                command_args = command[1:]

                try:
                    command_function(*command_args)
                except PasswordManagerException as e:
                    error_print(str(e))
                except KeyboardInterrupt:
                    continue
            else:
                error_print("Command not found!")

def _create_help():
    HELP_MESSAGE = 'Available commands:\n'
    commands_help = []

    for method_name in Password_Manager.__dict__.keys():
        if method_name.startswith("command_"):
            command_function = Password_Manager.__dict__[method_name]

            command_names = command_function.name
            command_names.sort(key=len, reverse=True)

            commands_help.append((command_names, command_function.__doc__.lower()))


    commands_help.sort(key=lambda x: x[0][0])

    for command_names, help_string in commands_help:
        HELP_MESSAGE += ", ".join(command_names).ljust(16) + help_string + "\n"

    return HELP_MESSAGE


Password_Manager.HELP_MESSAGE = _create_help()
del _create_help


def _create_list_of_commands():
    LIST_OF_COMMANDS = {}

    for method_name in Password_Manager.__dict__.keys():
        if method_name.startswith("command_"):
            command_function = Password_Manager.__dict__[method_name]

            command_names = command_function.name
            for command_name in command_names:
                if command_name in LIST_OF_COMMANDS:
                    raise Exception("Repeated command: %s"%command_name)
                else:
                    LIST_OF_COMMANDS[command_name] = method_name

    return LIST_OF_COMMANDS


Password_Manager.LIST_OF_COMMANDS = _create_list_of_commands()
del _create_list_of_commands


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Password manager.')
    parser.add_argument('filename', action="store", help="Path to file containing encrypted passwords")

    args = parser.parse_args()
    filename = args.filename


    Password_Manager(filename).run()
