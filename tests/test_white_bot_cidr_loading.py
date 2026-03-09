from utils.white_bots import (
    get_list_of_white_listed_bot_networks,
    IPv4or6Network
)
from utils.logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"


def write_temp_file(filepath: str, lines: list[str]):
    with open(filepath, 'w') as f:
        f.write('\n'.join(lines))


async def test_invalid_cidr():
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'googler'},
        logger=logger,
    )
    assert len(ip_networks) == 0


async def test_cidr_loading():
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'google'},
        logger=logger,
    )
    assert len(ip_networks) > 0

    for ip_net in ip_networks:
        assert isinstance(ip_net, IPv4or6Network)
        assert ip_net.network_address
        assert ip_net.prefixlen


async def test_ext_file_bad_file():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=["3232sdf asdfar32 rqef asdf adsf 2342"]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_missing_global_get_list():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "class TestClass:",
            "    hello: str"
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_invalid_global_get_list_signature():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "class TestClass:",
            "    hello: str",
            "def get_class_list(hello: str): ..."
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_global_get_list_is_coroutine():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "class TestClass:",
            "    hello: str",
            "async def get_class_list(): return TestClass"
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_global_get_list_is_list():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "class TestClass:",
            "    hello: str",
            "get_list = []"
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_invalid_returning_type_of_global_get_list():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "class TestClass:",
            "    hello: str",
            "def get_class_list(): return TestClass"
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_invalid_name_attribute():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "class TestClass:",
            "    hello: str",
            "def get_class_list(): return [TestClass]"
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_invalid_name_type():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "class TestClass:",
            "    name = 15",
            "def get_class_list(): return [TestClass]"
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_class_init_missing():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "class TestClass:",
            "    name = 'external'",
            "def get_class_list(): return [TestClass]"
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_class_init_bad_signature():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "class TestClass:",
            "    name = 'external'",
            "    def __init__(self): ...",
            "def get_class_list(): return [TestClass]"
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_class_get_list_not_coroutine():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "class TestClass:",
            "    name = 'external'",
            "    def __init__(self, logger): ...",
            "    def get_list(): ...",
            "def get_class_list(): return [TestClass]"
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_class_get_list_bad_signature():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "class TestClass:",
            "    name = 'external'",
            "    def __init__(self, logger): ...",
            "    async def get_list(self, extra: str): ...",
            "def get_class_list(): return [TestClass]"
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_class_get_list_none_returned():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "class TestClass:",
            "    name = 'external'",
            "    def __init__(self, logger): ...",
            "    async def get_list(self): ...",
            "def get_class_list(): return [TestClass]"
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_class_get_list_returned_invalid_list():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "class TestClass:",
            "    name = 'external'",
            "    def __init__(self, logger): ...",
            "    async def get_list(self): return [1, 3]",
            "def get_class_list(): return [TestClass]"
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 0


async def test_ext_file_class_get_list_returned_ok():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "import ipaddress",
            "class TestClass:",
            "    name = 'external'",
            "    def __init__(self, logger): ...",
            "    async def get_list(self):",
            "        return [ipaddress.IPv4Network('127.0.0.1/32')]",
            "def get_class_list(): return [TestClass]"
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 1


async def test_ext_file_missed_allowed_name():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "import ipaddress",
            "class TestClass:",
            "    name = 'external'",
            "    def __init__(self, logger): ...",
            "    async def get_list(self):",
            "        return [ipaddress.IPv4Network('127.0.0.1/32')]",
            "class TestClass2:",
            "    name = 'external2'",
            "    def __init__(self, logger): ...",
            "    async def get_list(self):",
            "        return [ipaddress.IPv4Network('127.0.0.2/32')]",
            "def get_class_list(): return [TestClass, TestClass2]",
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 1


async def test_ext_file_import_multiple_classes():
    filepath = '/tmp/external_white_list_bot.py'
    write_temp_file(
        filepath=filepath,
        lines=[
            "import ipaddress",
            "class TestClass:",
            "    name = 'external'",
            "    def __init__(self, logger): ...",
            "    async def get_list(self):",
            "        return [ipaddress.IPv4Network('127.0.0.1/32')]",
            "class TestClass2:",
            "    name = 'external2'",
            "    def __init__(self, logger): ...",
            "    async def get_list(self):",
            "        return [ipaddress.IPv4Network('127.0.0.2/32')]",
            "def get_class_list(): return [TestClass, TestClass2]",
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external', 'external2'},
        logger=logger,
        external_module_file_paths=[filepath]
    )
    assert len(ip_networks) == 2


async def test_ext_file_import_multiple_files():
    filepath1 = '/tmp/external_white_list_bot.py'
    filepath2 = '/tmp/external_white_list_bot_2.py'
    write_temp_file(
        filepath=filepath1,
        lines=[
            "import ipaddress",
            "class TestClass:",
            "    name = 'external'",
            "    def __init__(self, logger): ...",
            "    async def get_list(self):",
            "        return [ipaddress.IPv4Network('127.0.0.1/32')]",
            "class TestClass2:",
            "    name = 'external2'",
            "    def __init__(self, logger): ...",
            "    async def get_list(self):",
            "        return [ipaddress.IPv4Network('127.0.0.2/32')]",
            "def get_class_list(): return [TestClass, TestClass2]",
        ]
    )
    write_temp_file(
        filepath=filepath2,
        lines=[
            "import ipaddress",
            "class TestClass:",
            "    name = 'external3'",
            "    def __init__(self, logger): ...",
            "    async def get_list(self):",
            "        return [ipaddress.IPv4Network('127.0.0.3/32')]",
            "class TestClass2:",
            "    name = 'external4'",
            "    def __init__(self, logger): ...",
            "    async def get_list(self):",
            "        return [ipaddress.IPv4Network('127.0.0.4/32')]",
            "def get_class_list(): return [TestClass, TestClass2]",
        ]
    )
    ip_networks = await get_list_of_white_listed_bot_networks(
        allowed_sources={'external', 'external2', 'external3', 'external4'},
        logger=logger,
        external_module_file_paths=[filepath1, filepath2]
    )
    assert len(ip_networks) == 4
