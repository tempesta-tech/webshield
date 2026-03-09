import ipaddress
from dataclasses import dataclass
from typing import Optional
from ipaddress import IPv6Address

from clickhouse_connect import get_async_client
from clickhouse_connect.driver import AsyncClient

from utils.white_bots import IPv4or6Network


__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class BlockedUser:
    reason: int
    timestamp: float
    address: Optional[ipaddress.IPv6Address] = IPv6Address('::')
    tft: Optional[int] = 0
    tfh: Optional[int] = 0

    def as_tuple(self):
        return self.address, self.tft, self.tfh, self.reason, self.timestamp * 1000


@dataclass
class ClickhouseAccessLog:
    """
    Extends the ClickHouse client and describes the queries used in the application
    """

    host: str = "127.0.0.1"
    port: int = 8123
    user: str = "default"
    password: str = ""
    table_name: str = "access_log"
    database: str = "__default__"
    conn: AsyncClient = None

    async def connect(self):
        """
        Create a connection to the ClickHouse server
        """
        self.conn = await get_async_client(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database,
        )

    async def persistent_users_table_create(self):
        return await self.conn.query(
            """
            create table if not exists persistent_users (
                ip IPv6,
                PRIMARY KEY(ip)
            )
            """
        )

    async def persistent_users_table_drop(self):
        return await self.conn.query(
            """
            drop table if exists persistent_users
            """
        )

    async def persistent_users_table_truncate(self):
        return await self.conn.query(
            """
            truncate table persistent_users
            """
        )

    async def persistent_users_table_insert(self, values: list[list[str]]):
        return await self.conn.insert(
            table="persistent_users", data=values, column_names=["ip"]
        )

    async def persistent_users_all(self):
        return await self.conn.query(
            """
            SELECT *
            FROM persistent_users
            """
        )

    async def user_agents_table_drop(self):
        return await self.conn.query(
            """
            drop table if exists user_agents 
            """
        )

    async def user_agents_table_create(self):
        return await self.conn.query(
            """
            create table if not exists user_agents (
                name String,
                PRIMARY KEY(name)
            )
            """
        )

    async def user_agents_table_truncate(self):
        return await self.conn.query(
            """
            truncate table user_agents
            """
        )

    async def user_agents_table_insert(self, values: list[list[str]]):
        return await self.conn.insert(
            table="user_agents", data=values, column_names=["name"]
        )

    async def user_agents_all(self):
        return await self.conn.query(
            """
            SELECT *
            FROM user_agents
            """
        )

    async def access_log_truncate(self):
        return await self.conn.query("truncate table access_log")

    async def blocked_users_create_table(self):
        return await self.conn.query(
            """
            create table if not exists blocked_users (
                address IPv6,
                tft UInt64,
                tfh UInt64,
                reason UInt64,
                timestamp DateTime(3, 'UTC'),
                PRIMARY KEY(timestamp)
            )
            """
        )

    async def blocked_users_drop_table(self):
        return await self.conn.query("drop table blocked_users")

    async def blocked_users_add(self, blocked_users: list[BlockedUser]):
        await self.conn.insert(
            table='blocked_users',
            data=[blocked_user.as_tuple() for blocked_user in blocked_users],
            column_names=["address", "tft", "tfh", "reason", "timestamp"]
        )

    async def blocked_users_get_all(self) -> list[BlockedUser]:
        data = await self.conn.query("select * from blocked_users")
        return [BlockedUser(**user) for user in data.named_results()]

    async def bot_white_list_create_table(self):
        return await self.conn.query(
            """
            create table if not exists bots_white_list (
                cidr String,
                PRIMARY KEY(cidr)
            )
            """
        )

    async def bot_white_list_truncate(self):
        return await self.conn.query("truncate table bots_white_list")

    async def bot_white_list_insert(self, values: list[IPv4or6Network]):
        return await self.conn.insert(
            table='bots_white_list',
            data=[[str(cidr)] for cidr in values],
            column_names=["cidr"]
        )

    async def bot_white_list_all(self):
        return await self.conn.query(
            """
            SELECT *
            FROM bots_white_list
            """
        )

    async def bot_white_list_ip_trie_create(self):
        return await self.conn.query(
            """
            create dictionary if not exists bots_white_list_trie
            (
                cidr     String,
            )
            primary key cidr
            source(clickhouse(table bots_white_list))
            layout(IP_TRIE)
            lifetime(0);
            """
        )

    async def bot_white_list_ip_trie_refresh(self):
        return await self.conn.query('SYSTEM RELOAD DICTIONARY bots_white_list_trie;')
