import argparse
import os
from dataclasses import dataclass

from utils.logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"
__version__ = "0.1.1"


@dataclass
class CommandLineArgs:
    config: str = "/etc/tempesta-webshield/app.env"
    log_level: str = "INFO"
    verify: bool = False

    @classmethod
    def parse_args(cls) -> "CommandLineArgs":
        """
        Read command line arguments
        :return: key-value arguments
        """
        parser = argparse.ArgumentParser(
            description=f"""
Tempesta WebShield {__version__} (this version is experimental and should not be used in production).
Dynamically analyzes web traffic and blocks bad bots.
""",
            epilog="./app.py --config=/etc/tempesta-webshield/config.env",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            add_help=True,
        )
        parser.add_argument(
            "-c",
            "--config",
            type=str,
            default="/etc/tempesta-webshield/app.env",
            help="Path to the config file",
        )
        parser.add_argument(
            "-l",
            "--log-level",
            type=str,
            choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            default="INFO",
            help="Log level",
        )
        parser.add_argument(
            "--verify",
            action="store_true",
            help="Verify config params",
        )
        args = cls(**vars(parser.parse_args()))

        if not os.path.exists(args.config):
            logger.error(f"Config file not found at path: {args.config}")
            exit(1)

        return args
