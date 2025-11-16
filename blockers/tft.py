import os
import time

from blockers.base import BaseBlocker, PreparationError
from utils.datatypes import User
from utils.tf_config import TFConfig, TFHash
from utils.logger import logger
from utils.shell import run_in_shell

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TFtBlocker(BaseBlocker):
    def __init__(
        self,
        config: TFConfig,
        tempesta_executable_path: str = None,
        tempesta_config_path: str = None,
    ):
        self.config = config
        self.tempesta_executable_path = tempesta_executable_path
        self.tempesta_config_path = tempesta_config_path

    @staticmethod
    def name() -> str:
        return "tft"

    def __tempesta_app_exists(self) -> bool:
        if self.tempesta_executable_path and os.path.isfile(
            self.tempesta_executable_path
        ):
            return True

        return (
            run_in_shell("systemctl status tempesta-fw", raise_error=False).returncode == 0
        )

    def prepare(self):
        if not self.__tempesta_app_exists():
            raise PreparationError("Tempesta executable not found")

        try:
            self.config.verify_file()

        except (FileNotFoundError, PermissionError) as e:
            raise PreparationError(e)

    def load(self) -> dict[int, User]:
        self.config.load()
        current_time = int(time.time())
        result = dict()

        for hash_value in self.config.hashes:
            user = User(tft=[hash_value], blocked_at=current_time)
            result[hash(user)] = user

        return result

    def block(self, user: User):
        for hash_value in user.tft:
            if self.config.exists(hash_value):
                continue

            self.config.add(TFHash(value=hash_value, packets=0, connections=0))
            logger.warning(f"Blocked user {user} by tft")

    def release(self, user: User):
        for hash_value in user.tft:
            if not self.config.exists(hash_value):
                continue

            self.config.remove(hash_value)

    def apply(self):
        if not self.config.need_dump:
            return

        self.config.dump()

        if self.tempesta_executable_path:
            return run_in_shell(
                f"TFW_CFG_PATH={self.tempesta_config_path} {self.tempesta_executable_path} --reload",
                error="Tempesta FW could not be reloaded",
                raise_error=False,
            )

        run_in_shell(
            "systemctl reload tempesta-fw",
            error="Tempesta FW could not be reloaded",
            raise_error=False,
        )

    def info(self) -> list[User]:
        return [User(tft=[tf_hash.value]) for tf_hash in self.config.hashes.values()]
