import pytest

from utils.access_log import ClickhouseAccessLog


@pytest.fixture
async def access_log() -> ClickhouseAccessLog:
    _access_log = ClickhouseAccessLog()

    await _access_log.connect()
    await _access_log.user_agents_table_create()
    await _access_log.persistent_users_table_create()

    yield _access_log

    await _access_log.access_log_truncate()
    await _access_log.user_agents_table_truncate()
    await _access_log.persistent_users_table_truncate()
    await _access_log.conn.close()


@pytest.fixture
async def blocking_table(access_log):
    await access_log.blocked_users_create_table()
    yield
    await access_log.blocked_users_drop_table()
