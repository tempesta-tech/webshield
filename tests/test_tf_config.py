import os
import pytest

from utils.tf_config import TFConfig, TFHash

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@pytest.fixture
def config_path():
    path_to_config = "/tmp/tmp-hashes"

    with open(path_to_config, "w") as f:
        f.write(
            "hash aaaaaaa11111 3 4;\n"
            "  2222aaaaaaa 12   23444  ;  \n"
            " hash wrong222 12   ;  \n"
            "  hash wrong-again  ;  \n"
            "#commented  ;  \n"
        )
    yield path_to_config
    os.remove(path_to_config)


def test_config_does_not_exists():
    with pytest.raises(FileNotFoundError):
        config = TFConfig("/tmp/non-existing.conf")
        config.verify_file()


def test_load_hashes_from_file(config_path):
    config = TFConfig(config_path)
    config.load()

    assert len(config.hashes) == 1


def test_dump_file(config_path):
    config = TFConfig(config_path)
    config.load()

    config.hashes = {"test": TFHash(value="0", connections=1, packets=1)}
    config.dump()

    with open(config_path) as f:
        data = f.read()

    assert data == "hash 0 1 1;\n"


def test_modification(config_path):
    config = TFConfig(config_path)
    config.load()
    assert config.need_dump is False

    config.add(TFHash(value="100", connections=1, packets=2))
    assert config.need_dump == True

    config.dump()
    assert config.need_dump == False

    with open(config_path) as f:
        data = f.read()

    assert data == "hash aaaaaaa11111 3 4;\nhash 100 1 2;\n"

    config.remove("100")
    assert config.need_dump is True

    config.dump()
    assert config.need_dump == False

    with open(config_path) as f:
        data = f.read()

    assert data == "hash aaaaaaa11111 3 4;\n"
