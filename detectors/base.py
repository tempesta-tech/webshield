import abc
import asyncio
import math
import typing
from decimal import Decimal

from clickhouse_connect.driver import AsyncClient

from utils.access_log import ClickhouseAccessLog
from utils.datatypes import User

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from utils.logger import logger


class BaseDetector(metaclass=abc.ABCMeta):
    def __init__(
        self,
        access_log: ClickhouseAccessLog,
        default_threshold: Decimal = Decimal(10),
        intersection_percent: Decimal = Decimal(10),
        block_users_per_iteration: Decimal = Decimal(10),
    ):
        self._access_log = access_log
        self._default_threshold = default_threshold
        self._threshold = default_threshold
        self._intersection_percent = intersection_percent
        self.block_limit_per_check = block_users_per_iteration

    @property
    def db(self) -> AsyncClient:
        """
        The ClickHouse database connection
        """
        return self._access_log.conn

    @property
    def threshold(self) -> Decimal:
        """
        Current rounded threshold of the detector
        """
        return self._threshold.quantize(Decimal("0.01"))

    @threshold.setter
    def threshold(self, threshold: Decimal):
        self._threshold = threshold

    @staticmethod
    @abc.abstractmethod
    def name() -> str:
        """
        Name of the detector. Should be used in the config.
        """

    async def prepare(self):
        """
        Made some preparation, training, etc.
        """

    @abc.abstractmethod
    async def fetch_for_period(self, start_at: int, finish_at: int) -> list[User]:
        """
        Analyze user activity over the time period and identify the most risky users.

        :param start_at: period start time
        :param finish_at: period finish time
        :return: list of dangerous users
        """

    async def find_users(
        self, current_time: int, interval: int
    ) -> [list[User], list[User]]:
        """
        Get two groups of the most risky users for different time periods
        for further analysis.

        :param current_time: used as the current time in functional tests
        :param interval: used as the current time in functional tests
        :return: list of risky users
        """
        return await asyncio.gather(
            self.fetch_for_period(
                start_at=current_time - 2 * interval, finish_at=current_time - interval
            ),
            self.fetch_for_period(
                start_at=current_time - interval, finish_at=current_time
            ),
        )

    @property
    def validation_key(self) -> typing.Literal['ip', 'tft', 'tfh']:
        """
        The user model validation field
        """
        return 'ip'

    def validate_model(
        self, users_before: list[User], users_after: list[User]
    ) -> list[User]:
        """
        The model is an algorithm used to identify users relevant for blocking.

        It takes two groups of users from different past time periods and compares them.
        If the users from one period ago overlap with the users from two periods ago by at least [DETECTOR]_INTERSECTION_PERCENT,
        we assume this situation is normal since we are seeing the same users.
        However, if the users from one period ago were not in the previous group and their overlap is less than [DETECTOR]_INTERSECTION_PERCENT,
        we assume this is unusual traffic and block the entire new group of users.

        :param users_before: the group of users from two periods ago who generated the highest traffic
        :param users_after: the group of users from the previous period who generated the highest traffic

        :return: a list of users to be blocked
        """
        validation_key = self.validation_key

        users_map_before = dict()
        users_map_after = dict()

        for user in users_before:
            for _value in getattr(user, validation_key):
                users_map_before[_value] = user

        # prevent division by zero
        if not users_before:
            return []

        for user in users_after:
            for _value in getattr(user, validation_key):
                users_map_after[_value] = user

        # keys intersection
        intersection_keys = users_map_before.keys() & users_map_after.keys()
        intersection_keys_percent = (len(intersection_keys) / len(users_before)) * 100

        if intersection_keys_percent > self._intersection_percent:
            return []

        return users_after

    @staticmethod
    def arithmetic_mean(values: list[Decimal]) -> Decimal:
        """
        The arithmetic mean of the users' activity parameter
        """
        return Decimal(sum(values) / Decimal(len(values))).quantize(Decimal("0.01"))

    @staticmethod
    def standard_deviation(values: list[Decimal], arithmetic_mean: Decimal) -> Decimal:
        """
        The standard deviation (1 sigma) of the users' activity parameter
        """
        deviation = sum(
            map(lambda val: math.pow(val - arithmetic_mean, Decimal(2)), values)
        )
        deviation /= len(values)
        return Decimal(math.sqrt(deviation)).quantize(Decimal("0.01"))

    def get_values_for_threshold(self, users: list[User]) -> list[Decimal]:
        """
        Get the activity parameter of the user group

        :param users: list of users
        :return: list of user activity parameter values
        """
        return [user.value for user in users]

    def update_threshold(self, users: list[User]):
        """
        Set the new threshold

        :param users: list of users
        """
        if not users:
            self.threshold = self._default_threshold
            return

        values = self.get_values_for_threshold(users)
        arithmetic_mean = self.arithmetic_mean(values)
        standard_deviation = self.standard_deviation(
            values=values, arithmetic_mean=arithmetic_mean
        )
        self.threshold = arithmetic_mean + standard_deviation
        logger.debug(f'{self.name()} has new threshold: {self.threshold}')


class SQLBasedDetector(BaseDetector):
    @abc.abstractmethod
    def get_request(self, start_at: int, finish_at: int) -> str:
        """
        Return the SQL query for ClickHouse DB access log data to fetch
        the most risky users for the specified time period

        :param start_at: period start time
        :param finish_at: period finish time

        :return: sql query to run
        """

    async def fetch_for_period(self, start_at: int, finish_at: int) -> list[User]:
        """
        Run the SQL query and fetch the risky users for the specified time period

        :param start_at: period start time
        :param finish_at: period finish time
        """
        response = await self.db.query(self.get_request(start_at, finish_at))

        return [
            User(
                tft=[str(hex(tft))[2:] for tft in user[0]],
                tfh=[str(hex(tfh))[2:] for tfh in user[1]],
                ip=user[2],
                value=user[3],
                # type=user[4]
            )
            for user in response.result_rows
        ]
