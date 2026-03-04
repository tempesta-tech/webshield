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
