from typing import Union, List, Tuple
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from datetime import datetime
from os.path import isfile
from shutil import copyfile
from os import remove
import sqlite3 as sql
import logging
import base64



class PasswordNotSetException(Exception):
    def __init__(self, reason):
        super(PasswordNotSetException, self).__init__(reason)


class InvalidPasswordException(Exception):
    def __init__(self, reason):
        super(InvalidPasswordException, self).__init__(reason)


class Entry:
    def __init__(self, id_nr: int, name: str, description: str, username: str, password: str, last_changed):
        self.__id: int = id_nr
        self.name: str = name
        self.description: str = description
        self.username: str = username
        self.password: str = password
        self.last_changed: datetime = last_changed

    def get_id(self):
        return self.__id

    def set_id(self, id_nr: int):
        if self.__id < 0:
            self.__id = id_nr
        else:
            raise AttributeError("This attribute must not be modified, unless it was invalid before")

    def get_attributes(self) -> List:
        return [self.__id, self.name, self.description, self.username, self.password, self.last_changed]

    def get_update_attributes(self) -> List:
        return [self.name, self.description, self.username, self.password, self.last_changed, self.__id]


    def __repr__(self):
        return "Entry(" + ", ".join(map(repr, self.get_attributes())) + ")"

    def __str__(self):
        return self.__repr__()



class Data:
    ENC = "utf-8"

    def __init__(self, db_path: str, password: str):
        self.logger = logging.Logger(__name__)

        self.key: bytes = SHA256.new(password.encode(Data.ENC)).digest()

        self.db_path: str = db_path
        self.connection: sql.Connection = None
        self.cursor: sql.Cursor = None

        self.db_init()  # Connect to/Set up database

    def teardown(self):
        if self.connection is not None:
            self.connection.close()

    def update_key(self, key: str):
        # TODO: Check validity of current key, then update decrypt all passwords with current/old password and encrypt
        #       with new one (including reference entry)
        self.key = SHA256.new(key.encode(Data.ENC)).digest()

    def encrypt(self, value: str, encode=True) -> str:
        """
        Encrypt a given string with the key stored in the key attribute. Requires key to be non-empty.

        :param value: String that will be encrypted
        :param encode: If set, the encrypted string will be encoded with ENC codec
        :return: String containing the encrypted value

        :note: Taken from https://stackoverflow.com/questions/42568262/how-to-encrypt-text-with-a-password-in-python,
                then modified to this projects needs
        """

        if self.key == b"":
            raise PasswordNotSetException

        value = value.encode(Data.ENC)

        iv = Random.new().read(AES.block_size)  # Generate IV
        padding = AES.block_size - len(value) % AES.block_size  # Calculate padding

        encryptor = AES.new(self.key, AES.MODE_CBC, iv)

        value += bytes([padding]) * padding  # Add padding to value
        value_encrypted = iv + encryptor.encrypt(value)  # Encrypt value

        if encode:
            value_encrypted = base64.b64encode(value_encrypted).decode("utf-8")

        return value_encrypted

    def decrypt(self, value: str, decode=True) -> str:
        """
        Decrypt a given string with the key stored in the key attribute. Requires key to be non-empty.

        :param value: String that will be decrypted
        :param decode: If set, the decrypted string will be decoded with ENC codec
        :return: String containing the decrypted value

        :note: Taken from https://stackoverflow.com/questions/42568262/how-to-encrypt-text-with-a-password-in-python,
                then modified to this projects needs
        """

        if self.key == b"":
            raise PasswordNotSetException

        if decode:
            value = base64.b64decode(value.encode(Data.ENC))

        iv = value[:AES.block_size]

        decryptor = AES.new(self.key, AES.MODE_CBC, iv)

        value_decrypted = decryptor.decrypt(value[AES.block_size:])

        padding = value_decrypted[-1]
        if value_decrypted[-padding:] != bytes([padding]) * padding:
            # Invalid padding --> Most likely wrong password
            raise InvalidPasswordException("Invalid Padding")

        return value_decrypted[:-padding].decode(Data.ENC)

    def is_key_correct(self) -> bool:
        if self.cursor is None:
            self.logger.info("Cursor is None")
            return False

        ref_entry = self.get_entry_by_id(0)
        if ref_entry is None:
            self.logger.info("ref_entry is None")
            return False
        if ref_entry.password != ref_entry.name:
            raise InvalidPasswordException("Wrong Password")

        return True

    def db_init(self) -> bool:
        """
        Initialize connection to the database with the path specified in the db_path attribute

        :return: True if no database at the specified path existed or the existing database was corrupted/incomplete and
                    a new database had to be created. False otherwise
        """

        if self.db_path == "":
            raise ValueError("No path to database provided")

        self.logger.info("Trying to connect to database " + self.db_path)

        if not isfile(self.db_path):
            self.logger.warning("Database not found")

            self.db_setup()

            return True

        self.connection = sql.connect(self.db_path, detect_types=sql.PARSE_DECLTYPES)
        self.cursor = self.connection.cursor()

        if not self.is_key_correct():  # This returns False if the reference entry is missing or self.cursor is None
            self.logger.warning("Database corrupted. Recreating...")

            self.connection.close()

            copyfile(self.db_path, self.db_path + ".cor")
            remove(self.db_path)

            self.db_setup()

            return True

        # TODO: Validate database contents (all required tables exist etc.)

        return False

    def db_setup(self):
        """
        Setup new database at the path specified in the db_path attribute
        """

        self.logger.info("Setting up new database at " + self.db_path)

        if self.connection is not None:
            self.logger.info("Closing existing connection to database")
            try:
                self.connection.close()
            except Exception as error:
                self.logger.warning(error.with_traceback(error.__traceback__))

        self.connection = sql.connect(self.db_path, detect_types=sql.PARSE_DECLTYPES)
        self.cursor = self.connection.cursor()

        # Add table for storing username/password information
        self.cursor.execute("CREATE TABLE passwords ("
                            "   id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,"
                            "   name VARCHAR(128) UNIQUE NOT NULL,"
                            "   description VARCHAR(1024),"
                            "   username VARCHAR(128),"
                            "   password VARCHAR(1024),"
                            "   last_changed TIMESTAMP"
                            ");")
        self.cursor.execute("INSERT INTO passwords (id, name, password, last_changed)"
                            "   VALUES (?, ?, ?, ?);", (0, "reference", self.encrypt("reference"), datetime.now()))
        self.connection.commit()

        self.logger.info("Finished setting up database " + self.db_path)

    def get_entry_by_name(self, name: str) -> Union[Entry, None]:
        """
        Get a single entry from the database by its name

        :param name: Name value of the requested entry
        :return: Entry instance containing the requested database entry
        """

        self.cursor.execute(f"SELECT * FROM passwords WHERE name LIKE \"{name}\";")
        result = self.cursor.fetchone()

        if result is None:
            return None

        new_entry = Entry(*result)
        new_entry.password = self.decrypt(new_entry.password)

        return new_entry

    def get_entry_by_id(self, id_nr: int) -> Union[Entry, None]:
        """
        Get a single entry from the database by its id

        :param id_nr: id value of the requested entry
        :return: Entry instance containing the requested database entry
        """

        self.cursor.execute(f"SELECT * FROM passwords WHERE id = {id_nr};")
        result = self.cursor.fetchone()

        if result is None:
            return None

        new_entry = Entry(*result)
        new_entry.password = self.decrypt(new_entry.password)

        return new_entry

    def get_all_entries(self) -> List[Entry]:
        """
        Get all entries from the database

        :return: List of Entries; One entry for each row in the database
        """

        self.cursor.execute("SELECT * FROM passwords WHERE NOT id = 0;")
        results = list(map(list, self.cursor.fetchall()))

        for result in results:
            result[4] = self.decrypt(result[4])

        return list(map(lambda e: Entry(*e), results))  # Create Entry instance for each row

    def update_entry(self, entry: Entry):
        """
        Update values for given entry in the database

        :param entry: Instance of Entry containing the relevant data
        """

        if entry.get_id() <= 0:
            raise ValueError("Entry id must be at least 1")

        self.cursor.execute("UPDATE passwords SET"
                            "   name=?,"
                            "   description=?,"
                            "   username=?,"
                            "   password=?,"
                            "   last_changed=?"
                            "WHERE id = ?", entry.get_update_attributes())
        self.connection.commit()

    def add_entry(self, entry: Entry) -> Entry:
        """
        Add row to database with attributes stored in Entry instance

        :param entry: Instance of entry containing the relevant data
        :return: Entry instance with updated id attribute
        """

        values = entry.get_attributes()[1:]  # Get values without id
        values[3] = self.encrypt(values[3])  # Encrypt password for storage in database

        # Insert new row into database and commit changes
        self.cursor.execute(f"INSERT INTO passwords (name, description, username, password, last_changed) "
                            f"   VALUES (?, ?, ?, ?, ?)", values)
        self.connection.commit()

        # Get ID of the row that was just inserted and update the __id attribute of the Entry instance
        self.cursor.execute(f"SELECT id FROM passwords WHERE name LIKE \"{entry.name}\"")
        entry.set_id(self.cursor.fetchone()[0])

        return entry


def i_main():
    key = "password2"

    d = Data("data.db", key)

    while True:
        try:
            exec(input("$ "))
        except KeyboardInterrupt:
            break
        except Exception as error:
            print(error)

    d.teardown()


def main():
    key = "password"
    value = "secret"

    d = Data("data.db", key)


if __name__ == '__main__':
    i_main()
