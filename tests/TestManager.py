import unittest
from SafeGuard.Manager import Manager, Data, Entry
from os import remove
import sqlite3 as sql
import warnings
import time


class ManagerTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = Manager(db_path="test.db", password="key")

    def tearDown(self) -> None:
        self.manager.data.teardown()

        remove("test.db")

    def test_add_entry(self):
        self.manager.add_entry("test", "test description", "test_username", "test_password")

        self.assertEqual(1, len(self.manager.get_entries()))  # List of entries has size 1
        self.assertEqual(1, self.manager.get_entries()[0].get_id())  # New entry got id 1

    def test_add_entry_multiple(self):
        self.manager.add_entry("test1", "test1 description", "test1_username", "test1_password")
        self.manager.add_entry("test2", "test2 description", "test2_username", "test2_password")

        self.assertEqual(len(self.manager.get_entries()), 2)  # List of entries has size 1
        self.assertEqual(self.manager.get_entries()[1].get_id(), 2)  # New entry got id 1

    def test_add_entry_duplicate_name(self):
        self.manager.add_entry("test", "test1 description", "test1_username", "test1_password")

        with self.assertRaises(sql.IntegrityError):
            self.manager.add_entry("test", "test1 description", "test1_username", "test1_password")

    def test_update_entry(self):
        self.manager.add_entry("test", "test description", "test_username", "test_password")

        entry: Entry = self.manager.get_entries()[0]
        entry.description = "new description"

        self.manager.update_entry(entry)

        self.assertEqual(len(self.manager.get_entries()), 1)  # List of entries must still be 1
        self.assertEqual(entry, self.manager.get_entries()[0])

    def test_update_entry_duplicate_name(self):
        self.manager.add_entry("test1", "test1 description", "test1_username", "test1_password")
        self.manager.add_entry("test2", "test2 description", "test2_username", "test2_password")

        entry: Entry = self.manager.get_entries()[1]
        entry.name = "test1"

        with self.assertRaises(sql.IntegrityError):
            self.manager.update_entry(entry)

    def test_delete_entry(self):
        self.manager.add_entry("test1", "test1 description", "test1_username", "test1_password")
        self.manager.add_entry("test2", "test2 description", "test2_username", "test2_password")

        entry: Entry = self.manager.get_entries()[0]

        self.manager.delete_entry(entry)

        self.assertEqual(1, len(self.manager.get_entries()))
        self.assertNotIn(entry, self.manager.get_entries())

    def test_delete_entry_duplicate(self):
        self.manager.add_entry("test1", "test1 description", "test1_username", "test1_password")
        self.manager.add_entry("test2", "test2 description", "test2_username", "test2_password")

        entry: Entry = self.manager.get_entries()[0]

        self.manager.delete_entry(entry)

        with self.assertRaises(ValueError):
            self.manager.delete_entry(entry)

    def test_update_entries(self):
        entries_empty = self.manager.get_entries()

        self.manager.add_entry("test1", "test1 description", "test1_username", "test1_password")

        entries_one = self.manager.get_entries()

        self.manager.add_entry("test2", "test2 description", "test2_username", "test2_password")

        entries_two = self.manager.get_entries()

        self.assertNotEqual(entries_empty, entries_one)
        self.assertNotEqual(entries_empty, entries_two)
        self.assertNotEqual(entries_one, entries_two)


if __name__ == '__main__':
    unittest.main()
