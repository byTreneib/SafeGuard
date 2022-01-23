from typing import Union, List, Tuple, Optional
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

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.get_attributes() == other.get_attributes()

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
        """
        Initialize class instance with path to database and password
        :param db_path: path to database as string
        :param password: password for the values in the database
        """

        self.logger = logging.Logger(__name__)  # Create logger instance

        self.key: bytes = SHA256.new(password.encode(Data.ENC)).digest()  # Set password hash

        self.db_path: str = db_path
        self.connection: Optional[sql.Connection] = None
        self.cursor: Optional[sql.Cursor] = None

        self.db_init()  # Connect to/Set up database

    def __del__(self):
        """
        Cleanup class instance when being deleted
        """

        self.teardown()

    def teardown(self):
        """
        Teardown method
        """

        # Disconnect from database, if possible
        if self.connection is not None:
            self.connection.close()

    def update_key(self, key: str):
        """
        Change the key used for encryption and decryption of the passwords stored in the database

        :param key: New password as string
        """

        # Check validity of current password before changing
        if not self.is_key_correct():
            raise InvalidPasswordException("Wrong password")

        all_entries = self.get_all_entries()  # Get and decrypt all entries with current password

        self.key = SHA256.new(key.encode(Data.ENC)).digest()  # Update key attribute to new password hash

        # Update all entries
        for entry in all_entries:
            self.update_entry(entry)

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
        """
        Checks if the password hash currently stored in the key attribute is correct
        :return: True if the password hash is correct, False otherwise
        """

        if self.cursor is None:
            self.logger.warning("Cursor is None")
            raise AttributeError("No database cursor")

        # Get and decrypt reference entry (id 0) from database
        ref_entry = self.get_entry_by_id(0)
        if ref_entry is None:
            self.logger.warning("ref_entry is None")
            raise ValueError("No reference entry found in database")
        if ref_entry.password != ref_entry.name:
            # Current password hash does not decrypt database contents --> Return False
            return False

        return True  # Current password hash did successfully decrypt database reference entry --> Return True


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

        try:
            if not self.is_key_correct():  # This returns False if the reference entry is missing or self.cursor is None
                raise InvalidPasswordException("Wrong password")
        except ValueError:
            self.db_recreate()

            return True

        self.cursor.execute("SELECT * FROM sqlite_master WHERE type = \"table\" AND name = \"passwords\";")
        if len(self.cursor.fetchall()) != 1:
            self.db_recreate()

            return True

        return False

    def db_recreate(self):
        """
        Save copy of the current database file with '.cor' ending, then removes original and runs database setup
        """

        self.logger.warning("Database corrupted. Recreating...")

        self.connection.close()

        copyfile(self.db_path, self.db_path + ".cor")
        remove(self.db_path)

        self.db_setup()

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
        # Add reference entry into the passwords table
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

        # Get one row from database where name matches
        self.cursor.execute(f"SELECT * FROM passwords WHERE name LIKE \"{name}\";")
        result = self.cursor.fetchone()

        if result is None:
            return None

        # Create Entry instance from database result
        new_entry = Entry(*result)
        new_entry.password = self.decrypt(new_entry.password)

        return new_entry

    def get_entry_by_id(self, id_nr: int) -> Union[Entry, None]:
        """
        Get a single entry from the database by its id

        :param id_nr: id value of the requested entry
        :return: Entry instance containing the requested database entry
        """

        # Get one row from database where id matches
        self.cursor.execute(f"SELECT * FROM passwords WHERE id = {id_nr};")
        result = self.cursor.fetchone()

        if result is None:
            return None

        # Create entry instance from database result
        new_entry = Entry(*result)
        new_entry.password = self.decrypt(new_entry.password)

        return new_entry

    def get_all_entries(self) -> List[Entry]:
        """
        Get all entries from the database

        :return: List of Entries; One entry for each row in the database
        """

        # Get all rows except for reference entry from database and cast rows to lists
        self.cursor.execute("SELECT * FROM passwords WHERE NOT id = 0;")
        results = list(map(list, self.cursor.fetchall()))

        # decrypt the passwords
        for result in results:
            result[4] = self.decrypt(result[4])

        # Create Entry instance from each row and return list of all Entry instances
        return list(map(lambda e: Entry(*e), results))  # Create Entry instance for each row

    def update_entry(self, entry: Entry):
        """
        Update values for given entry in the database

        :param entry: Instance of Entry containing the relevant data
        """

        if entry.get_id() <= 0:
            raise ValueError("Entry id must be at least 1")

        values = entry.get_update_attributes()[:-1]  # Get values without id
        values[3] = self.encrypt(values[3])  # Encrypt password for storage in database

        # Update values for row with matching id and commit changes
        self.cursor.execute(f"UPDATE passwords SET"
                            f"  name = \"{entry.name}\","
                            f"  description = \"{entry.description}\","
                            f"  username = \"{entry.username}\","
                            f"  password = \"{self.encrypt(entry.password)}\","
                            f"  last_changed = \"{entry.last_changed}\""
                            f"WHERE id = {entry.get_id()}")
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

    def remove_entry(self, entry: Entry):
        """
        Remove row with attributes stored in Entry instance

        :param entry: Entry instance containing the relevant data
        """

        self.cursor.execute(f"DELETE FROM passwords WHERE id = {entry.get_id()}")
        self.connection.commit()


class Manager:
    def __init__(self, db_path: str, password: str):
        self.logger = logging.Logger(__name__)
        self.data = Data(db_path, password)

        self.__entries: List[Entry] = []

    def __del__(self):
        """
        Clean up class instance when being deleted
        """

        self.data.teardown()
        del self.__entries

    def update_entries(self):
        """
        Update __entries attribute from database
        """

        self.__entries = self.data.get_all_entries()

    def get_entries(self) -> List[Entry]:
        """
        Update, then get copy of private list of entries

        :return: Copy of list of Entry instances
        """

        self.update_entries()
        return self.__entries.copy()

    def add_entry(self, name: str, description: str, username: str, password: str):
        """
        Create Entry instance and add it to the database

        :param name: Name of new entry as string
        :param description: Description of new entry as string
        :param username: Username for new entry as string
        :param password: Password for new entry as string
        :return: Entry instance containing id for newly inserted row in the database and last_changed timestamp
        """

        self.__entries.append(self.data.add_entry(Entry(-1, name, description, username, password, datetime.now())))

    def delete_entry(self, entry: Entry):
        """
        Remove specified entry from database

        :param entry: Entry instance
        """

        self.data.remove_entry(entry)
        self.__entries.remove(entry)

    def update_entry(self, entry: Entry):
        """
        Update values of specified entry in database

        :param entry: Entry instance
        """

        if entry not in self.__entries:
            self.logger.error("entry must be in __entries list")
            return
        self.data.update_entry(entry)


def i_main():
    key = "password2"

    m = Manager("data.db", key)

    while True:
        try:
            exec(input("$ "))
        except KeyboardInterrupt:
            break
        except Exception as error:
            print(str(error.__class__.__name__) + ": " + str(error))

    del m


if __name__ == '__main__':
    i_main()
