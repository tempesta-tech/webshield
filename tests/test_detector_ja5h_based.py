from decimal import Decimal
from ipaddress import IPv4Address

import pytest

from detectors.ja5h import (
    Ja5hAccumulativeTimeDetector,
    Ja5hErrorRequestDetector,
    Ja5hRPSDetector,
)
from utils.datatypes import User

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@pytest.fixture(autouse=True)
async def data(access_log):
    await access_log.conn.query(
        """
        insert into access_log values
        (cast('1751535005' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
        (cast('1751535006' as DateTime64(3, 'UTC')), '127.0.0.2', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent2', 12, 22, 0),
        (cast('1751535007' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent2', 13, 23, 0),
        (cast('1751535007' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent3', 13, 23, 0),
        (cast('1751535007' as DateTime64(3, 'UTC')), '127.0.0.4', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent4', 13, 23, 0)
        """
    )


async def test_rps(access_log):
    detector = Ja5hRPSDetector(
        access_log=access_log,
        default_threshold=Decimal("2"),
        difference_multiplier=Decimal("10"),
    )
    users_before, users_after = await detector.find_users(
        current_time=1751535010, interval=5
    )
    assert users_before == []
    assert len(users_after) == 1
    assert users_after[0].ja5t == ['d']
    assert set(users_after[0].ip) == {
        IPv4Address("127.0.0.3"),
        IPv4Address("127.0.0.4"),
    }


async def test_rps_with_user_agents(access_log):
    await access_log.user_agents_table_insert([["UserAgent"], ["UserAgent4"]])
    detector = Ja5hRPSDetector(
        access_log=access_log,
        default_threshold=Decimal("2"),
        difference_multiplier=Decimal("10"),
    )
    users_before, users_after = await detector.find_users(
        current_time=1751535010, interval=5
    )
    assert users_before == []
    assert users_after == [User(ja5t=['d'], ja5h=['17'], ip=[IPv4Address("127.0.0.3")])]


async def test_rps_with_persistent_users(access_log):
    await access_log.persistent_users_table_insert(
        [
            ["127.0.0.3"],
        ]
    )
    detector = Ja5hRPSDetector(
        access_log=access_log,
        default_threshold=Decimal("2"),
        difference_multiplier=Decimal("10"),
    )
    users_before, users_after = await detector.find_users(
        current_time=1751535010, interval=5
    )
    assert users_before == []
    assert users_after == []


async def test_errors(access_log):
    detector = Ja5hErrorRequestDetector(
        access_log=access_log,
        default_threshold=Decimal("2"),
        difference_multiplier=Decimal("10"),
        allowed_statues=[300],
    )
    users_before, users_after = await detector.find_users(
        current_time=1751535010, interval=5
    )
    assert users_before == []
    assert users_after == [
        User(
            ja5t=['d'],
            ja5h=['17'],
            ip=[IPv4Address("127.0.0.4"), IPv4Address("127.0.0.3")],
        )
    ]


async def test_errors_with_user_agents(access_log):
    await access_log.user_agents_table_insert([["UserAgent"], ["UserAgent3"]])
    detector = Ja5hErrorRequestDetector(
        access_log=access_log,
        default_threshold=Decimal("2"),
        difference_multiplier=Decimal("10"),
        allowed_statues=[300],
    )
    users_before, users_after = await detector.find_users(
        current_time=1751535010, interval=5
    )
    assert users_before == []
    assert len(users_after) == 1
    assert users_after[0].ja5t == ['d']
    assert set(users_after[0].ip) == {
        IPv4Address("127.0.0.3"),
        IPv4Address("127.0.0.4"),
    }


async def test_errors_with_persistent_users(access_log):
    await access_log.persistent_users_table_insert(
        [
            ["127.0.0.3"],
        ]
    )
    detector = Ja5hErrorRequestDetector(
        access_log=access_log,
        default_threshold=Decimal("2"),
        difference_multiplier=Decimal("10"),
        allowed_statues=[300],
    )
    users_before, users_after = await detector.find_users(
        current_time=1751535010, interval=5
    )
    assert users_before == []
    assert users_after == []


async def test_errors_forbidden_statuses(access_log):
    detector = Ja5hErrorRequestDetector(
        access_log=access_log,
        default_threshold=Decimal("2"),
        difference_multiplier=Decimal("10"),
        allowed_statues=[200],
    )
    users_before, users_after = await detector.find_users(
        current_time=1751535010, interval=5
    )
    assert users_before == []
    assert users_after == []


async def test_time(access_log):
    detector = Ja5hAccumulativeTimeDetector(
        access_log=access_log,
        default_threshold=Decimal("15"),
        difference_multiplier=Decimal("10"),
    )
    users_before, users_after = await detector.find_users(
        current_time=1751535010, interval=5
    )
    assert users_before == []
    assert len(users_after) == 1
    assert users_after[0].ja5t == ['d']
    assert set(users_after[0].ip) == {
        IPv4Address("127.0.0.3"),
        IPv4Address("127.0.0.4"),
    }


async def test_time_with_user_agents(access_log):
    await access_log.user_agents_table_insert([["UserAgent"], ["UserAgent3"]])
    detector = Ja5hAccumulativeTimeDetector(
        access_log=access_log,
        default_threshold=Decimal("15"),
        difference_multiplier=Decimal("10"),
    )
    users_before, users_after = await detector.find_users(
        current_time=1751535010, interval=5
    )
    assert users_before == []
    assert len(users_after) == 1
    assert users_after[0].ja5t == ['d']
    assert set(users_after[0].ip) == {
        IPv4Address("127.0.0.3"),
        IPv4Address("127.0.0.4"),
    }


async def test_time_with_persistent_users(access_log):
    await access_log.persistent_users_table_insert(
        [
            ["127.0.0.3"],
        ]
    )
    detector = Ja5hAccumulativeTimeDetector(
        access_log=access_log,
        default_threshold=Decimal("15"),
        difference_multiplier=Decimal("10"),
    )
    users_before, users_after = await detector.find_users(
        current_time=1751535010, interval=5
    )
    assert users_before == []
    assert users_after == []
