import os
import re
import stat
from dataclasses import dataclass
from typing import Dict

from utils.logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class TFHash:
    value: str
    connections: int
    packets: int


class TFConfig:
    """
    Tempesta Fingerprints (TF) Config Manager
    """

    hash_pattern = re.compile(
        r"[\t\s]*hash*"
        r"[\t\s]*(?P<hash>\w+)[\t\s]+"
        r"(?P<connections>\d+)[\t\s]+"
        r"(?P<packets>\d+)[\t\s]*;[\t\s]*"
    )

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.hashes: Dict[str, TFHash] = {}
        self.need_dump: bool = False

    @staticmethod
    def format_line(tf_hash: TFHash) -> str:
        """
        Create a string representation of a TF hash.

        :param tf_hash: TF hash value.
        :return: Formatted string representation of the TF hash.
        """
        return f"hash {tf_hash.value} {tf_hash.connections} {tf_hash.packets};\n"

    def verify_file(self):
        """
        Check whether the file exists and has the correct permissions.
        Creates an empty file with correct permissions if it doesn't exist.
        Raises an exception if the directory doesn't exist.
        """
        directory = os.path.dirname(self.file_path)
        if directory and not os.path.isdir(directory):
            logger.error(f"Directory `{directory}` does not exist")
            raise FileNotFoundError(f"Directory `{directory}` does not exist")

        if not os.path.isfile(self.file_path):
            # Create empty file with correct permissions
            with open(self.file_path, "w") as f:
                pass
            file_permissions = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
            os.chmod(self.file_path, file_permissions)
            logger.info(f"Created empty file `{self.file_path}` with permissions {oct(file_permissions)}")

        if not os.access(self.file_path, os.W_OK):
            logger.error(
                f"File `{self.file_path}` is not writable. App does not have enough permissions."
            )
            raise PermissionError

    def load(self):
        """
        Parse the TF configuration file and store the loaded hashes.
        """
        with open(self.file_path, "r") as f:
            for line in f.readlines():
                result = re.match(self.hash_pattern, line)

                if not result:
                    logger.warning(f"Could not parse hash: `{line}`")
                    continue

                hash_value = result.group("hash")
                self.hashes[hash_value] = TFHash(
                    value=result.group("hash"),
                    connections=result.group("connections"),
                    packets=result.group("packets"),
                )

    def dump(self):
        """
        Dump the local storage of TF hashes into the configuration file.
        """
        with open(self.file_path, "w") as f:
            for value in self.hashes.values():
                f.write(self.format_line(value))

        self.need_dump = False

    def exists(self, tf_hash: str) -> bool:
        """
        Check if a TF hash exists in local storage.

        :param tf_hash: TF hash value.
        :return: True if the hash exists, False otherwise.
        """
        return tf_hash in self.hashes

    def add(self, tf_hash: TFHash):
        """
        Add a new TF hash to local storage.

        :param tf_hash: TF hash value.
        """
        self.hashes[tf_hash.value] = tf_hash
        self.need_dump = True

    def remove(self, tf_hash: str):
        """
        Remove a TF hash from local storage.

        :param tf_hash: TF hash value.
        """
        self.hashes.pop(tf_hash)
        self.need_dump = True
