from decimal import Decimal
from typing import Literal

from pydantic_settings import BaseSettings

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class AppConfig(BaseSettings):
    path_to_tft_config: str = "/etc/tempesta/tft/blocked.conf"
    path_to_tfh_config: str = "/etc/tempesta/tfh/blocked.conf"

    clickhouse_host: str = "192.168.0.104"
    clickhouse_port: int = 8123
    clickhouse_user: str = "default"
    clickhouse_password: str = ""
    clickhouse_table_name: str = "access_log"
    clickhouse_database: str = "default"

    persistent_users_allow: bool = True
    persistent_users_window_offset_min: int = 60
    persistent_users_window_duration_min: int = 60

    detectors: set[
        Literal[
            "ip_rps",
            "ip_time",
            "ip_errors",
            "tft_rps",
            "tft_time",
            "tft_errors",
            "tfh_rps",
            "tfh_time",
            "tfh_errors",
            "geoip",
        ]
    ] = {"tft_rps", "tft_time", "tft_errors"}

    blocking_types: set[Literal["tft", "tfh", "ipset", "nftables"]] = {"tft"}
    blocking_window_duration_sec: int = 10
    blocking_ipset_name: str = "tempesta_blocked_ips"
    blocking_time_min: int = 60
    blocking_release_time_min: int = 1

    training_mode: Literal["off", "historical", "real"] = "off"
    training_mode_duration_min: int = 10

    detector_ip_rps_default_threshold: Decimal = Decimal(10)
    detector_ip_rps_intersection_percent: Decimal = Decimal(10)
    detector_ip_rps_block_users_per_iteration: Decimal = Decimal(10)

    detector_ip_time_default_threshold: Decimal = Decimal(10)
    detector_ip_time_intersection_percent: Decimal = Decimal(10)
    detector_ip_time_block_users_per_iteration: Decimal = Decimal(10)

    detector_ip_errors_default_threshold: Decimal = Decimal(10)
    detector_ip_errors_intersection_percent: Decimal = Decimal(10)
    detector_ip_errors_block_users_per_iteration: Decimal = Decimal(10)
    detector_ip_errors_allowed_statuses: list[int] = [
        100,
        101,
        200,
        201,
        204,
        300,
        301,
        302,
        303,
        304,
        305,
        307,
        308,
        400,
        401,
        403,
    ]

    detector_tft_rps_default_threshold: Decimal = Decimal(10)
    detector_tft_rps_intersection_percent: Decimal = Decimal(10)
    detector_tft_rps_block_users_per_iteration: Decimal = Decimal(10)

    detector_tft_time_default_threshold: Decimal = Decimal(10)
    detector_tft_time_intersection_percent: Decimal = Decimal(10)
    detector_tft_time_block_users_per_iteration: Decimal = Decimal(10)

    detector_tft_errors_default_threshold: Decimal = Decimal(10)
    detector_tft_errors_intersection_percent: Decimal = Decimal(10)
    detector_tft_errors_block_users_per_iteration: Decimal = Decimal(10)
    detector_tft_errors_allowed_statuses: list[int] = [
        100,
        101,
        200,
        201,
        204,
        300,
        301,
        302,
        303,
        304,
        305,
        307,
        308,
        400,
        401,
        403,
    ]

    detector_tfh_rps_default_threshold: Decimal = Decimal(10)
    detector_tfh_rps_intersection_percent: Decimal = Decimal(10)
    detector_tfh_rps_block_users_per_iteration: Decimal = Decimal(10)

    detector_tfh_time_default_threshold: Decimal = Decimal(10)
    detector_tfh_time_intersection_percent: Decimal = Decimal(10)
    detector_tfh_time_block_users_per_iteration: Decimal = Decimal(10)

    detector_tfh_errors_default_threshold: Decimal = Decimal(10)
    detector_tfh_errors_intersection_percent: Decimal = Decimal(10)
    detector_tfh_errors_block_users_per_iteration: Decimal = Decimal(10)
    detector_tfh_errors_allowed_statuses: list[int] = [
        100,
        101,
        200,
        201,
        204,
        300,
        301,
        302,
        303,
        304,
        305,
        307,
        308,
        400,
        401,
        403,
    ]

    detector_geoip_rps_default_threshold: Decimal = Decimal(10)
    detector_geoip_intersection_percent: Decimal = Decimal(10)
    detector_geoip_block_users_per_iteration: Decimal = Decimal(10)
    detector_geoip_path_allowed_cities_list: str = (
        "/etc/tempesta-webshield/allowed_cities.txt"
    )
    detector_geoip_path_to_db: str = "/etc/tempesta-webshield/city.db"

    tempesta_executable_path: str = ""
    tempesta_config_path: str = ""
    allowed_user_agents_file_path: str = (
        "/etc/tempesta-webshield/allow_user_agents.txt"
    )
    log_level: str = "INFO"

    @classmethod
    def read(cls, path: str) -> str:
        with open(path, "r") as f:
            return f.read()

    @property
    def training_mode_duration_sec(self) -> int:
        return self.training_mode_duration_min * 60

    @property
    def persistent_users_window_offset_sec(self) -> int:
        return self.persistent_users_window_offset_min * 60

    @property
    def persistent_users_window_duration_sec(self) -> int:
        return self.persistent_users_window_duration_min * 60

    @property
    def blocking_release_time_sec(self) -> int:
        return self.blocking_release_time_min * 60

    @property
    def blocking_time_sec(self) -> int:
        return self.blocking_time_min * 60
