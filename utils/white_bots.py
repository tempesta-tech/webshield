import abc
import asyncio
import inspect
import importlib.util
import logging
import typing
import traceback

from ipaddress import ip_network, IPv6Network, IPv4Network

import aiohttp


__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"


IPv4or6Network = IPv4Network | IPv6Network


class GoogleWhiteListIpRecord(typing.TypedDict):
    ipv6Prefix: str | None
    ipv4Prefix: str | None


class BaseWhiteIpListSource:
    name: str

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    @abc.abstractmethod
    async def get_resources(self) -> typing.List[typing.Any]:
        """
        Read from the disk or download from the internet
        some list of ip addresses or networks
        """

    @abc.abstractmethod
    def parse(self, item: typing.Any) -> IPv6Network:
        """
        Parse the fetched element and convert it into the
        ip network
        """

    async def get_list(self) -> list[IPv6Network]:
        """
        Fetch the list of ip addresses or networks
        and convert them into the IP Networks Generator
        """
        data = await self.get_resources()
        results = []
        for item in data:
            results.append(self.parse(item))

        return results


class GoogleWhiteIpListSource(BaseWhiteIpListSource):
    name = 'google'
    urls = [
        "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
        "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json",
        "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json",
        "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers-google.json"
    ]

    async def get_resource(self, client: aiohttp.ClientSession, url: str) -> list[GoogleWhiteListIpRecord]:
        async with client.get(url) as response:
            if not response.status == 200:
                self.logger.warning(
                    f'Could not fetch data about white ip list: '
                    f'{url}, code={response.status}'
                )
                return []

            decoded_response = await response.json()
            return decoded_response['prefixes']


    async def get_resources(self) -> typing.List[GoogleWhiteListIpRecord]:
        responses = []

        async with aiohttp.ClientSession() as session:
            for url in self.urls:
                white_ips = await self.get_resource(session, url)
                responses.extend(white_ips)

        return responses

    def parse(self, item: GoogleWhiteListIpRecord) -> IPv4or6Network:
        net = item.get('ipv4Prefix') or item.get('ipv6Prefix')
        return ip_network(net)


def import_external_bots(
        logger: logging.Logger,
        external_func_name: str,
        file_paths: list[str]
) -> list[typing.Type[BaseWhiteIpListSource]]:
    imported_classes = []

    for file_path in file_paths:
        try:
            spec = importlib.util.spec_from_file_location('external_loaded_bot_module', file_path)

            if not spec:
                logger.warning(f'Can not import module "{file_path}". File is missing')
                continue

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

        except SyntaxError:
            logger.warning(f'Can not import module "{file_path}": {traceback.format_exc()}')
            continue

        except Exception as error:
            logger.warning(f'Can not import module "{file_path}": {error}')
            continue

        get_class_list_function = getattr(module, external_func_name, None)

        if not inspect.isfunction(get_class_list_function) or inspect.iscoroutinefunction(get_class_list_function):
            logger.warning(f'The global function "{external_func_name}" should be regular function with '
                           f'the signature "def {external_func_name}(): ..."')
            continue

        if not get_class_list_function:
            logger.warning(f'Can not find the function "{external_func_name}" inside the file "{file_path}"')
            continue

        get_class_list_function_signature = inspect.signature(get_class_list_function)

        if len(get_class_list_function_signature.parameters) != 0:
            logger.warning(
                f'Invalid signature of the function returning list of classes '
                f'"{external_func_name}" inside the file "{file_path}".'
                f' The correct one is "def {external_func_name}(): ..." '
                f'your realization is "def {external_func_name}{get_class_list_function_signature}"'
            )
            continue

        try:
            returned_classes = get_class_list_function()
        except Exception as error:
            logger.warning(
                f'Can not execute external module function '
                f'"{file_path}:{external_func_name}". Error: {error}'
            )
            continue

        if not isinstance(returned_classes, list):
            logger.warning(
                f'The external module function '
                f'"{file_path}:{external_func_name}" should return the list of classes'
            )
            continue

        for returned_class in returned_classes:
            name_attribute = getattr(returned_class, 'name', None)

            if not isinstance(name_attribute, str):
                logger.warning(f'Class "{returned_class}" does not have non-empty string class attribute "name"')
                continue

            init_func = getattr(returned_class, '__init__')

            if not init_func:
                logger.warning(f'Class "{returned_class}" does not have "__init__" method')
                continue

            init_signature = inspect.signature(init_func)

            if len(init_signature.parameters) != 2:
                logger.warning(
                    f'Class "{returned_class}.__init__" has invalid signature. '
                    f'The proper one is "def __init__(self, logger: logging.Logger):" '
                    f'your realization is "def __init__{init_signature}"'
                )
                continue

            if 'self' not in init_signature.parameters or 'logger' not in init_signature.parameters:
                logger.warning(
                    f'Class "{returned_class}.__init__" has invalid signature. '
                    f'The proper one is "def __init__(self, logger: logging.Logger):" '
                    f'your realization is "def __init__{init_signature}"'
                )
                continue

            get_list_coroutine = getattr(returned_class, 'get_list', None)

            if not get_list_coroutine:
                logger.warning(f'Class "{returned_class}" does not have coroutine "get_list"')
                continue

            if not inspect.iscoroutinefunction(get_list_coroutine):
                logger.warning(f'Class "{returned_class}.get_list" is not coroutine')
                continue

            get_list_coroutine_signature = inspect.signature(get_list_coroutine)

            if len(get_list_coroutine_signature.parameters) != 1:
                logger.warning(
                    f'Class "{returned_class}.get_list" has invalid signature. '
                    f'The proper one is "async def get_list(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:"'
                    f' your realization is "async def get_list{get_class_list_function_signature}"'
                )
                continue

            if 'self' not in get_list_coroutine_signature.parameters:
                logger.warning(
                    f'Class "{returned_class}.get_list" has invalid signature. '
                    f'The proper one is "async def get_list(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network:"'
                    f' your realization is "async def get_list{get_class_list_function_signature}"'
                )
                continue

            imported_classes.append(returned_class)

    return imported_classes


async def filter_invalid_data_types(
        coroutine: typing.Coroutine,
        logger: logging.Logger,
) -> list[IPv4or6Network]:
    result = []
    elements = await coroutine

    if not elements:
        return []

    for element in elements:
        if not isinstance(element, IPv4Network) and not isinstance(element, IPv6Network):
            logger.warning(
                f'Skipped element "{element}". It has invalid type = "{type(element)}". '
                f'It should be of type IPv4Network or IPv6Network'
            )
            continue

        result.append(element)

    return result


async def get_list_of_white_listed_bot_networks(
        allowed_sources: set[str],
        logger: logging.Logger,
        external_module_file_paths: list[str] = (),
) -> list[IPv4or6Network]:
    """
    Get the list of allowed IP networks from bot IPs sources

    :param external_module_file_paths: list of external file paths with defined bots whitelist
    :param allowed_sources: list of source names
    :param logger: the app logger
    :return: list of all loaded ip networks
    """
    internal_classes = [GoogleWhiteIpListSource]
    allowed_classes: list[typing.Type[BaseWhiteIpListSource]] = []

    for source_class in internal_classes:
        if source_class.name in allowed_sources:
            allowed_classes.append(source_class)

    external_classes = import_external_bots(
        logger=logger,
        external_func_name='get_class_list',
        file_paths=external_module_file_paths
    )

    for source_class in external_classes:
        if source_class.name in allowed_sources:
            allowed_classes.append(source_class)

    sources = [source(logger=logger) for source in allowed_classes]

    try:
        ip_network_list = await asyncio.gather(*[
            filter_invalid_data_types(
                coroutine=source.get_list(),
                logger=logger
            )
            for source in sources
        ])
        return sum(ip_network_list, [])

    except Exception:
        logger.error(f'Can not load bots white list: {traceback.format_exc()}')

    return []
