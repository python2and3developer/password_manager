#encoding: utf-8

import sys
import re
import getpass
import string
import os
import subprocess
import platform
import readline
import itertools
import shlex
import hashlib
import json
import random
import inspect
import datetime

import pyaes
import pyperclip


# TODO
# - Python 3 support
# - Possibility to protect keys of accounts with a second password
# - Command to show data of only specific account and key
#    If a key is protected, a second password is required to print value or copy value to clipboard.
#    A key is protected if it contains the attribute 'protected' or 'encrypted' to True
# - Different cryptographic methods
# - If defined the environment variable EDITOR_FOR_PASSWORD_MANAGER, then all editions will be done using your that editor and saving intermediate results in temporal documents.
# - More personalization for the generation of random passwords
# - Create key with random password
# - Edit key with random password
# - Add creation and modification timestamps for accounts and keys of accounts
# - Consider these libraries:
#       https://github.com/italorossi/ishell
#       https://github.com/jonathanslenders/python-prompt-toolkit
# Print and ask copy to clipboard
# Mirar esto:
# https://stackoverflow.com/questions/42568262/how-to-encrypt-text-with-a-value-in-python/44212550
#  hashlib.sha256("Nobody inspects the spammish repetition").hexdigest()


PASSWORD_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

CLIPBOARD_ENCODING = 'utf-8'

LIST_OF_TRUE_VALUES = ["y", "yes", "1", "on"]
LIST_OF_FALSE_VALUES = ["n", "no", "0", "off"]

SIGNATURE = 'Ps54kNc8ZnUqWgxZ'


def get_boolean(c):
    if isinstance(c, bool):
        return c
    else:
        c = c.strip().lower()
        if c in LIST_OF_TRUE_VALUES:
            return True                
        elif show_values in LIST_OF_FALSE_VALUES:
            return False


def create_timestamp():
    return datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S %Z %Y")


def generate_password(password_length):
    letters = string.ascii_lowercase
    password = ''.join(random.choice(letters) for i in range(password_length))

    return password


def which(program):
    import os
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    return None


def executable_exists(name):
    return which(name) is not None


class PasswordManagerException(Exception):
    def __init__(self, msg=None):
        self._msg = msg

    def __str__(self):
        if self._msg:
            return self._msg
        else:
            return self.__doc__


class BadArguments(PasswordManagerException):
    """Bad arguments passed to command"""

class AccountNotFoundException(PasswordManagerException):
    """Account not found"""


class AccountExistsException(PasswordManagerException):
    """Account name already exits"""

class AccountKeyIndexException(PasswordManagerException):
    """Invalid index key in account"""


class AccountIsRemovedException(PasswordManagerException):
    """Account is already removed. Not possible to do more operations"""


class EncryptionException(PasswordManagerException):
    """Cannot encrypt data!"""


# https://stackoverflow.com/questions/1854/python-what-os-am-i-running-on
if platform.system() == "Windows":
    def clear_screen():
        os.system('cls')
else:
    def clear_screen():
        os.system('reset')


def warn_print(s):
    print("[!] WARNINIG: {0}".format(s))

def error_print(s):
    print("[x] ERROR: {0}".format(s))

def info_print(s):
    print("[*] {0}".format(s))



def echo(text, indent=0, indent_char=" ", prefix=""):
    print("\n".join(prefix + indent_char*indent + l for l in text.splitlines()))


def decrypt(enc_data, password):  
    key_32 = hashlib.sha256(password).digest()


    dec_data = pyaes.AESModeOfOperationCTR(key_32).decrypt(enc_data)
    dec_data = dec_data.decode("utf-8")

    return dec_data


def encrypt(dec_data, password):
    key_32 = hashlib.sha256(password).digest()

    dec_data = dec_data.encode("utf-8")    
    enc_data = pyaes.AESModeOfOperationCTR(key_32).encrypt(dec_data)

    return enc_data


def check_if_account_is_removed(func):
    def wrapper(self, *args, **kwargs):
        if self._is_removed:
            raise AccountIsRemovedException
        return func(self, *args, **kwargs)
    return wrapper


class Account(object):
    def __init__(self, password_manager, root):
        self.root = root
        self._password_manager = password_manager

        self._is_removed = False

    @property
    def is_private(self):
        return "private" in self.root and self.root["private"]

    @check_if_account_is_removed
    def save(self):
        last_modification = create_timestamp()
        self.root["last_modification"] = last_modification

        self._password_manager.save_accounts()

    def _check_index(self, index):
        try:
            index = int(index)
        except ValueError:
            raise AccountKeyIndexException("Not a valid index: %s"%index)

        if 0 <= index < len(self.root["data"]):
            return index    
        else:
            raise AccountKeyIndexException("Index out of range: %s"%index)

    @property
    def num_keys(self):
        return len(self.root["data"])


    def get_key(self, index):
        index = self._check_index(index)
        
        return self.root["data"][index]

    def del_key(self, index):
        index = self._check_index(index)

        del self.root["data"][index]
        
    def set_key(self, index, key=None, value=None):
        index = self._check_index(index)
        item_data = self.root["data"][index]

        if key is not None:
            item_data["key"] = key

        if value is not None:
            item_data["value"] = value

    def add_key(self, key, value):
        key = self._normalize_key_name(key)
        value = self._normalize_value(value)

        self.root["data"].append({
            "key": key,
            "value": value
        })

    def add_random_password_key(self, key, password_length=10):
        key = self._normalize_key_name(key)
        value = generate_password(password_length)

        self.root["data"].append({
            "key": key,
            "value": value
        })

    def get_value_by_name(self, key):
        key = self._normalize_key_name(key)
        for item_data in self.root["data"]:
            if item_data["key"] == key:
                return item_data["value"]
        
    @property
    def name(self):
        return self.root['account_name']

    @name.setter
    def name(self, account_name):
        account_name = self._normalize_account_name(account_name)
        self.root["account_name"] = account_name

    @property
    def data(self):
        return self.root["data"]

    @staticmethod
    def _normalize_account_name(account_name):
        account_name = " ".join(account_name.lower().strip().split())
        account_name = account_name.replace("*", "")
        account_name = account_name.replace("?", "")

        return account_name

    @staticmethod
    def _normalize_key_name(key):
        key = " ".join(key.strip().lower().split())
        return key

    @staticmethod
    def _normalize_value(value):
        value = value.strip()
        return value

    @classmethod
    def create_account(cls, password_manager, account_name, keys):
        account_name = cls._normalize_account_name(account_name)

        account_element = {'account_name': account_name, "data":[]}

        for key, value in keys.items():
            key = cls._normalize_key_name(key)
            value = cls._normalize_value(value)

            account_element["data"].append({
                "key": key,
                "value": value
            })

        password_manager._root["accounts"].append(account_element)

        return Account(password_manager, account_element)

    def dump(self, show_values=False, graph=False, prefix_name="", password=None):
        name = prefix_name + self.name.encode(sys.stdout.encoding)

        if graph:
            echo("|\n+ %s"%name)
        else:
            echo("ACCOUNT NAME: {0}".format(name))
            echo("DATA")

        
        for index, item_data in enumerate(self.data):
            key = item_data["key"]
            key = key.encode(sys.stdout.encoding)

            if show_values and (not self.is_private or (self.is_private and password is not None)):
                value = item_data["value"]
                if password:
                    value = decrypt(value, password)

                value = value.encode(sys.stdout.encoding)

                if graph:
                    echo("+ %d. %s: %s"%(key, value), indent=4, prefix="|")
                else:
                    echo("%d. %s: %s"%(index, key, value), indent=4)

            else:
                if graph:
                    echo("|\n+ %s"%key, indent=4, prefix="|")
                else:
                    echo("%d. %s"%(index, key), indent=4)

    def remove(self):
        self._password_manager._root["accounts"].remove(self.root)
        self._password_manager.save_accounts()

        self._is_removed = True

def cmd(*args):
    def decorator(f):
        cmd_name = list(args)
        cmd_name.sort(key=len, reverse=True)

        f._cmd_name = cmd_name
        f._cmd = True

        return f
    return decorator


class Password_Manager_Meta(type):
    def __new__(meta, name, bases, dct):
        list_of_commands = meta._create_list_of_commands(dct)

        dct["LIST_OF_COMMANDS"] = meta._create_list_of_command_names(list_of_commands)
        dct["HELP_MESSAGE"] = meta._create_help(list_of_commands)

        return super(Password_Manager_Meta, meta).__new__(meta, name, bases, dct)

    @staticmethod
    def _create_list_of_commands(dct):
        list_of_commands = []

        for method_name in dct.keys():
            method_function = dct[method_name]

            if hasattr(method_function, "_cmd"):
                list_of_commands.append((method_name, method_function))

        return list_of_commands

    @staticmethod
    def _create_list_of_command_names(command_methods):
        LIST_OF_COMMANDS = {}

        for method_name, method_function in command_methods:
            command_names = method_function._cmd_name
            for command_name in command_names:
                if command_name in LIST_OF_COMMANDS:
                    raise Exception("Repeated command: %s"%command_name)
                else:
                    LIST_OF_COMMANDS[command_name] = method_name

        return LIST_OF_COMMANDS

    @staticmethod
    def _create_help(command_methods):
        HELP_MESSAGE = 'Available commands:\n'
        commands_help = []

        for method_name, method_function in command_methods:
            command_names = method_function._cmd_name

            if hasattr(method_function, "__doc__") and method_function.__doc__:
                help_msg = method_function.__doc__.lower()
            else:
                help_msg = ""

            commands_help.append((command_names, help_msg))

        commands_help.sort(key=lambda x: x[0][0])

        for command_names, help_string in commands_help:
            HELP_MESSAGE += ", ".join(command_names).ljust(18) + help_string + "\n"

        return HELP_MESSAGE



class Password_Manager(object):
    __metaclass__ = Password_Manager_Meta
    #PROMPT = "Command:"
    PROMPT = ">"

    def __init__(self, filename, master_password=None, title="Password Manager"):
        self._filename = filename
        self._master_password = master_password

        self._show_values = False

        self._root = None
        self._title = title

    def all_accounts(self):
        list_of_accounts = []

        for account_element in self._root["accounts"]:
            list_of_accounts.append(Account(self, account_element))

        return list_of_accounts

    def save_accounts(self):
        modification_date = create_timestamp()
        self._root["last_modification"] = modification_date
        self._root["password_manager"] = SIGNATURE

        encrypted_data = encrypt(json.dumps(self._root), self._master_password)
        with open(self._filename, "wb") as f:
            f.write(encrypted_data)


    def _print_all_accounts(self):
        list_of_accounts = self.all_accounts()

        if list_of_accounts:
            echo("List of accounts:")
            for account_index, account in enumerate(list_of_accounts):
                echo("%d. "%account_index + account.name)

        else:
            warn_print("No account")

    def _ask_hidden_value(self, key_name, old_value=None):
        while True:
            if old_value is None or old_value == "":
                new_value = getpass.getpass("%s: "%key_name)
            else:
                new_value = getpass.getpass("%s [%s]: "%(key_name, old_value))

            if new_value == "": return

            new_value = new_value.decode(sys.stdin.encoding)

            repeat_value = getpass.getpass("Repeat %s: "%key_name)

            if new_value == repeat_value:
                return new_value
            else:
                warn_print("values don't coincide")

    def _ask_confirmation(self, msg):

        while True:
            answer = raw_input(msg + " Answer 'y' to confirm...\n").strip().lower()

            if answer in ("y", "yes"):
                return True
            elif answer in ("n", "no", ""):
                return False


    def _ask_account_index(self, index=None):
        if index is None:
            index = raw_input("Write an account index: ")

        account = self.find_account_by_index(index)

        if account is None:
            raise AccountNotFoundException

        return account

    def find_account_by_index(self, index):
        try:
            index = int(index)
        except ValueError:
            pass
        else:
            list_of_accounts = self.all_accounts()
            if 0 <= index < len(list_of_accounts):
                return list_of_accounts[index]

    def find_account(self, pattern):
        account = self.find_account_by_index(pattern)
        if account:
            return account

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

            for account in self.all_accounts():
                if re.search(pattern, account.name, flags=re.I):
                    return account
        else:
            pattern = Account._normalize_account_name(pattern)

            for account in self.all_accounts():
                if pattern == account.name:
                    return account

            for account in self.all_accounts():
                if pattern in account.name:
                    return account

    def _create_account(self, account_name=None):
        """Add account"""

        if account_name is None:
            account_name = raw_input("Account name:\n ")
            account_name = account_name.strip()

            if account_name == "": return

            account_name = account_name.decode(sys.stdin.encoding)

        keys = {}

        while True:
            if not self._ask_confirmation("Do you want to create a key?"): break

            key = raw_input("\nKey: ")
            key = key.decode(sys.stdin.encoding)

            print("Value: ")

            value_lines = []

            white_line = False
            while True:
                line = raw_input()
                if line:
                    value_lines.append(line.decode(sys.stdin.encoding))
                    white_line = False
                else:
                    if white_line:
                        break
                    else:
                        white_line = True


            value = '\n'.join(value_lines)
            value = value.strip()

            keys[key] = value

        account = Account.create_account(self, account_name, keys)
        return account

    def _rename(self, account):
        account_name = raw_input("New name for account: ")
        account_name = account_name.decode(sys.stdin.encoding)

        account.name = account_name
        account.save()

        info_print("Account successfully renamed!")        


    @cmd("create")
    def _command_create(self, account_name=None):
        """Create a new account"""

        account = self._create_account(account_name)
        account.save()

        info_print("Account added!")

    @cmd("list", "l")
    def _command_list(self):
        """List all available account by name"""
        self._print_all_accounts()


    @cmd("delete", "d")
    def _command_delete(self, index=None):
        """Delete account"""
        
        account = self._ask_account_index(index)

        if self._ask_confirmation("are you sure that you want to delete this account '%s'?"%account.name):
            account.dump(show_values=self._show_values)

            account.remove()

            info_print("Account deleted!")

    @cmd("clipboard", "c")
    def _command_clipboard(self, index=None, key=None):
        """Copy value to clipboard"""
        account = self._ask_account_index(index)
        
        if key is None:
            num_keys = account.num_keys
            if num_keys == 0:
                value = None
            elif num_keys == 1:
                value = account.get_key(0)["value"]
            else:
                account.dump(show_values=False)
                key_index = raw_input("\nKey index: ")

                value = account.get_key(key_index)["value"]
        else:
            value = account.get_value_by_name(key)

        if value:
            pyperclip.copy(value)

            info_print("value copied to clipboard!")
        else:
            warn_print("key not found!")

    @cmd("edit", "e")
    def _command_edit(self, index=None):
        """Edit account"""

        account = self._ask_account_index(index)

        while True:
            print("")
            account.dump(show_values=self._show_values)

            print("\nSelect option:")
            print("  1. Edit key name")
            print("  2. Edit value")
            print("  3. Delete key")
            print("  4. Add key")
            print("  5. Add key with random password")
            print("  6. Rename account")
            print("  7. Exit")

            option = raw_input()
            option = option.strip()


            if option == "1":
                index = raw_input("Key index: ")
                index = index.decode(sys.stdin.encoding)

                key = raw_input("Key [%s]: "%account.get_key(index)["key"])
                key = key.decode(sys.stdin.encoding)
                
                account.set_key(index, key=key)
                account.save()
                
            elif option == "2":
                index = raw_input("Key index: ")
                index = index.decode(sys.stdin.encoding)

                value = raw_input("Value [%s]: "%account.get_key(index)["value"])
                value = value.decode(sys.stdin.encoding)
                
                account.set_key(index, value=value)
                account.save()
                
            elif option == "3":
                index = raw_input("Key index: ")
                index = index.decode(sys.stdin.encoding)

                account.del_key(index)
                account.save()

            elif option == "4":
                key = raw_input("Key: ")
                key = key.decode(sys.stdin.encoding)

                value = raw_input("Value: ")
                value = value.decode(sys.stdin.encoding)

                account.add_key(key, value)
                account.save()

            elif option == "5":
                key = raw_input("Key: ")
                key = key.decode(sys.stdin.encoding)

                password_length = raw_input("Password length: ")
                password_length = password_length.decode(sys.stdin.encoding)

                password_length = password_length.strip()

                try:
                    password_length = int(password_length)
                except ValueError:
                    raise PasswordManagerException("Password length is not integer")

                account.add_random_password_key(key, password_length=password_length)
                account.save()

            elif option == "6":
                self._rename(account)

            elif option == "7":
                break

            else:
                print("Invalid option: %s"%option)

    @cmd("rename")
    def _command_rename(self, index=None):
        """Rename account"""

        account = self._ask_account_index(index)
        self._rename(account)

    @cmd("find", "f")
    def _command_find(self, account_pattern=None, show_values=None):
        """Find account"""

        if account_pattern is None:
            account_pattern = raw_input("Write an account pattern: ")
            account_pattern = account_pattern.strip()

            if account_pattern == "": return
            
            account_pattern = account_pattern.decode(sys.stdin.encoding)

        account = self.find_account(account_pattern)
        if account is None:
            raise AccountNotFoundException
        else:
            account.dump(show_values=self._show_values)

    @cmd("print", "p")
    def _command_print(self, index=None, show_values=None):
        """Print account"""

        account = self._ask_account_index(index)
        if show_values is None:
            show_values = self._show_values
        else:
            show_values = get_boolean(show_values)
            if show_values is None:
                raise PasswordManagerException("Not valid 'show_values' parameter: %s"%show_values)

        account.dump(show_values=show_values)

    @cmd("print_all")
    def _command_print_all(self, show_values=None):
        """Print all accounts"""

        if show_values is None:
            show_values = self._show_values
        else:
            show_values = get_boolean(show_values)
            if show_values is None:
                raise PasswordManagerException("Not valid 'show_values' parameter: %s"%show_values)

        for i, account in enumerate(self.all_accounts()):
            account.dump(show_values=show_values, graph=True, prefix_name="%d. "%i)

    @cmd("show", "s")
    def _command_show(self, index=None):
        """Show all data of specific account"""
        self._command_print(index=index, show_values=True)

    @cmd("show_values")
    def _command_show_values(self):
        """Show values"""

        self._show_values = True
        print("All values will be shown now!")

    @cmd("hide_values")
    def _command_hide_values(self):
        """Hide values"""

        self._show_values = False

        print("All values will be hidden now!")

    @cmd("dump")
    def _command_dump(self):
        """Dump file content in plain text"""
        echo(json.dumps(self._root, indent=4))

    @cmd("help", "h")
    def _command_help(self):
        """Print help"""
        print(self.HELP_MESSAGE)

    @cmd("clear")
    def _command_clear(self):
        """Clear screen"""

        clear_screen()
        print(self.HELP_MESSAGE)

    @cmd("quit", "q")
    def _command_exit(self):
        """Quit"""

        clear_screen()
        exit()

    @cmd("random_pass")
    def _command_generate_password(self, password_length=10):
        """Generate random password"""

        password_length = int(password_length)

        password = generate_password(password_length)
        print(password)

    def run(self):
        if os.path.isfile(self._filename):
            new_file = False
        else:
            print("")
            info_print("A new value file will be created.")
            new_file = True

        if self._master_password is None:
            try:
                master_password = getpass.getpass("Write the master password.\n")
            except KeyboardInterrupt:
                return

            if master_password == "":
                return

        if new_file:
            if self._master_password is None:
                try:
                    repeated_master_password = getpass.getpass("Repeat password.\n")
                except KeyboardInterrupt:
                    return

                if master_password != repeated_master_password:
                    error_print("values doesn't coincide")
                    return

                self._master_password = master_password


            creation_date = create_timestamp()
            self._root = {
                "accounts": [],
                "password_manager": SIGNATURE,
                "creation_date": creation_date,
                "last_modification": creation_date
            }

            self.save_accounts()
        else:
            self._master_password = master_password

            with open(self._filename, "rb") as f:
                enc_data = f.read()

            try:
                root = decrypt(enc_data, self._master_password)
            except ValueError:
                error_print("Wrong Password")
                return
           
            try:
                self._root = json.loads(root)
            except ValueError:
                error_print("Wrong Password")
                return

            if "password_manager" not in self._root or self._root["password_manager"] != SIGNATURE:
                error_print("Wrong Password")
                return               

        clear_screen()

        header = "-"*len(self._title) + "\n" + self._title + "\n" + "-"*len(self._title) + "\n\n" + self.HELP_MESSAGE
        print(header)

        self._print_all_accounts()
        print("\nPlease enter a command.")


        while True:
            try:
                user_input = raw_input("\n%s "%self.PROMPT)
            except KeyboardInterrupt:
                return

            print("")

            command = shlex.split(user_input)
            command_name = command[0].lower()

            if command_name in self.LIST_OF_COMMANDS:
                command_function = getattr(self, self.LIST_OF_COMMANDS[command_name])
                args = []
                kwargs = {}

                for t in command[1:]:
                    if "=" in t:
                        key, value = t.split("=")
                        kwargs[key] = value
                    else:
                        args.append(t)

                func_args = inspect.getargspec(command_function).args[1:]

                try:
                    if len(args) > len(func_args):
                        raise BadArguments

                    func_args = func_args[len(args):]

                    for kw in kwargs:
                        if kw not in func_args:
                            raise BadArguments

                except BadArguments:
                    error_print("Bad arguments")
                    continue

                try:
                    command_function(*args, **kwargs)
                except PasswordManagerException as e:
                    error_print(str(e))
                except KeyboardInterrupt:
                    continue
            else:
                error_print("Command not found!")

            print("\n")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='value manager.')
    parser.add_argument('filename', action="store", help="Path to file containing encrypted values")

    args = parser.parse_args()
    filename = args.filename

    Password_Manager(filename).run()
