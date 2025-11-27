#!/usr/bin/python3
import asyncio
import logging
import signal

import blockers
from cli import CommandLineArgs
from config import AppConfig
from core.context import AppContext
from core.executor import run_app
from detectors.geoip import GeoIPDetector
from detectors.ip import (
    IPAccumulativeTimeDetector,
    IPErrorRequestDetector,
    IPRPSDetector,
)
from detectors.tft import (
    TFtAccumulativeTimeDetector,
    TFtErrorRequestDetector,
    TFtRPSDetector,
)
from detectors.tfh import (
    TFhAccumulativeTimeDetector,
    TFhErrorRequestDetector,
    TFhRPSDetector,
)
from utils.access_log import ClickhouseAccessLog
from utils.tf_config import TFConfig
from utils.logger import logger
from utils.user_agents import UserAgentsManager

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import asyncio
import signal


shutdown_task = None


async def shutdown(loop, signal=None):
    if signal:
        logger.info(f"Received exit signal {signal.name}...")

    logger.info("Cancelling tasks...")
    tasks = [t for t in asyncio.all_tasks(loop) if t is not asyncio.current_task(loop)]
    for task in tasks:
        task.cancel()

    if tasks:
        try:
            # Wait a bit for tasks to finish their cleanup
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=1.0,
            )
        except asyncio.TimeoutError:
            logger.warning("Timed out while waiting for tasks to cancel.")

    logger.info("Shutdown complete.")


def setup_signal_handlers(loop):
    def _handler(sig):
        global shutdown_task
        if shutdown_task is None or shutdown_task.done():
            shutdown_task = asyncio.create_task(shutdown(loop, signal=sig))

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda s=sig: _handler(s))


async def main(app_config):
    clickhouse_client = ClickhouseAccessLog(
        host=app_config.clickhouse_host,
        port=app_config.clickhouse_port,
        user=app_config.clickhouse_user,
        password=app_config.clickhouse_password,
        table_name=app_config.clickhouse_table_name,
        database=app_config.clickhouse_database,
    )
    context = AppContext(
        blockers={
            blockers.TFtBlocker.name(): blockers.TFtBlocker(
                config=TFConfig(file_path=app_config.path_to_tft_config),
                tempesta_executable_path=app_config.tempesta_executable_path,
                tempesta_config_path=app_config.tempesta_config_path,
            ),
            blockers.TFhBlocker.name(): blockers.TFhBlocker(
                config=TFConfig(file_path=app_config.path_to_tfh_config),
                tempesta_executable_path=app_config.tempesta_executable_path,
                tempesta_config_path=app_config.tempesta_config_path,
            ),
            blockers.IpSetBlocker.name(): blockers.IpSetBlocker(
                blocking_ip_set_name=app_config.blocking_ipset_name,
            ),
            blockers.NFTBlocker.name(): blockers.NFTBlocker(
                blocking_table_name=app_config.blocking_ipset_name,
            ),
        },
        detectors={
            IPRPSDetector.name(): IPRPSDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_ip_rps_default_threshold,
                intersection_percent=app_config.detector_ip_rps_intersection_percent,
                block_users_per_iteration=app_config.detector_ip_rps_block_users_per_iteration,
            ),
            IPAccumulativeTimeDetector.name(): IPAccumulativeTimeDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_ip_time_default_threshold,
                intersection_percent=app_config.detector_ip_time_intersection_percent,
                block_users_per_iteration=app_config.detector_ip_time_block_users_per_iteration,
            ),
            IPErrorRequestDetector.name(): IPErrorRequestDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_ip_errors_default_threshold,
                intersection_percent=app_config.detector_ip_errors_intersection_percent,
                block_users_per_iteration=app_config.detector_ip_errors_block_users_per_iteration,
                allowed_statues=app_config.detector_ip_errors_allowed_statuses,
            ),
            TFtRPSDetector.name(): TFtRPSDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_tft_rps_default_threshold,
                intersection_percent=app_config.detector_tft_rps_intersection_percent,
                block_users_per_iteration=app_config.detector_tft_rps_block_users_per_iteration,
            ),
            TFtAccumulativeTimeDetector.name(): TFtAccumulativeTimeDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_tft_time_default_threshold,
                intersection_percent=app_config.detector_tft_time_intersection_percent,
                block_users_per_iteration=app_config.detector_tft_time_block_users_per_iteration,
            ),
            TFtErrorRequestDetector.name(): TFtErrorRequestDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_tft_errors_default_threshold,
                intersection_percent=app_config.detector_tft_errors_intersection_percent,
                block_users_per_iteration=app_config.detector_tft_errors_block_users_per_iteration,
                allowed_statues=app_config.detector_tft_errors_allowed_statuses,
            ),
            TFhRPSDetector.name(): TFhRPSDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_tfh_rps_default_threshold,
                intersection_percent=app_config.detector_tfh_rps_intersection_percent,
                block_users_per_iteration=app_config.detector_tfh_rps_block_users_per_iteration,
            ),
            TFhAccumulativeTimeDetector.name(): TFhAccumulativeTimeDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_tfh_time_default_threshold,
                intersection_percent=app_config.detector_tfh_time_intersection_percent,
                block_users_per_iteration=app_config.detector_tfh_time_block_users_per_iteration,
            ),
            TFhErrorRequestDetector.name(): TFtErrorRequestDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_tfh_errors_default_threshold,
                intersection_percent=app_config.detector_tfh_errors_intersection_percent,
                block_users_per_iteration=app_config.detector_tfh_errors_block_users_per_iteration,
                allowed_statues=app_config.detector_tfh_errors_allowed_statuses,
            ),
            GeoIPDetector.name(): GeoIPDetector(
                access_log=clickhouse_client,
                intersection_percent=app_config.detector_geoip_intersection_percent,
                block_users_per_iteration=app_config.detector_geoip_block_users_per_iteration,
                path_to_db=app_config.detector_geoip_path_to_db,
                path_to_allowed_cities_list=app_config.detector_geoip_path_allowed_cities_list,
            ),
        },
        clickhouse_client=clickhouse_client,
        app_config=app_config,
        user_agent_manager=UserAgentsManager(
            clickhouse_client=clickhouse_client,
            config_path=app_config.allowed_user_agents_file_path,
        ),
    )

    await run_app(context)


if __name__ == "__main__":
    logger.info("Starting Tempesta WebShield")

    args = CommandLineArgs.parse_args()
    app_config = AppConfig(_env_file=args.config)
    logger.setLevel(getattr(logging, args.log_level or app_config.log_level, "INFO"))

    if args.verify:
        exit(0)

    # Explicitly create and set a new event loop to get rid off default signal handler.
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    setup_signal_handlers(loop)

    try:
        loop.run_until_complete(main(app_config))
    except asyncio.CancelledError:
        # Normal path on signal termination: main() was cancelled
        logger.info("Main task cancelled during shutdown")
    finally:
        # Make sure all pending tasks (including shutdown) are finished
        if shutdown_task is not None and not shutdown_task.done():
            loop.run_until_complete(shutdown_task)
        loop.close()
