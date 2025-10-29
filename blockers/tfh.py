import time

from blockers.tft import TFtBlocker
from utils.datatypes import User
from utils.tf_config import TFHash
from utils.logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TFhBlocker(TFtBlocker):

    @staticmethod
    def name() -> str:
        return "tfh"

    def load(self) -> dict[int, User]:
        self.config.load()
        current_time = int(time.time())
        result = dict()

        for hash_value in self.config.hashes:
            user = User(tfh=[hash_value], blocked_at=current_time)
            result[hash(user)] = user

        return result

    def block(self, user: User):
        if self.config.exists(user.tfh[0]):
            return None

        self.config.add(TFHash(value=user.tfh[0], packets=0, connections=0))
        logger.warning(f"Blocked user {user} by tfh")

    def release(self, user: User):
        if not self.config.exists(user.tfh[0]):
            return None

        self.config.remove(user.tfh[0])

    def info(self) -> list[User]:
        return [User(tfh=[tf_hash.value]) for tf_hash in self.config.hashes.values()]
