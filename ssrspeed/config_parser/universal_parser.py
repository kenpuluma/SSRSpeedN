# -*- coding: utf-8 -*-

import binascii
from copy import deepcopy
import logging
import requests
from urllib.parse import urlparse

from ..utils import b64plus
from ..types.nodes import NodeShadowsocks, NodeShadowsocksR, NodeV2Ray, NodeTrojan
from .ss import ParserShadowsocksBasic, ParserShadowsocksSIP002
from .ssr import ParserShadowsocksR
from .vmess import ParserVmess
from .clash_parser import ParserClash
from .node_filter import NodeFilter
from .trojan import TrojanParser

from config import config

PROXY_SETTINGS = config["proxy"]
LOCAL_ADDRESS = config["localAddress"]
LOCAL_PORT = config["localPort"]
TIMEOUT = 10

logger = logging.getLogger("Sub")


class UniversalParser:
    def __init__(self):
        self.__nodes = []

    @staticmethod
    def __parse_group_marker(line: str):
        stripped = line.strip()
        marker = "# group:"
        if stripped.lower().startswith(marker):
            return stripped[len(marker):].strip()
        return None

    @staticmethod
    def __is_proxy_link(line: str) -> bool:
        return (
            line.startswith("ss://") or
            line.startswith("ssr://") or
            line.startswith("vmess://") or
            line.startswith("trojan://")
        )

    @staticmethod
    def __is_subscription_url(line: str) -> bool:
        try:
            parsed = urlparse(line.strip())
        except ValueError:
            return False
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)

    @staticmethod
    def web_config_to_node(configs: list) -> list:
        result = []
        for config in configs:
            _type = config.get("type", "N/A")
            if _type == "Shadowsocks":
                result.append(NodeShadowsocks(config["config"]))
            elif _type == "ShadowsocksR":
                result.append(NodeShadowsocksR(config["config"]))
            elif _type == "V2Ray":
                result.append(NodeV2Ray(config["config"]))
            else:
                logger.warn(f"Unknown node type: {_type}")
        return result

    @property
    def nodes(self):
        return deepcopy(self.__nodes)

    def __clean_nodes(self):
        self.__nodes.clear()

    def set_nodes(self, nodes: list):
        self.__clean_nodes()
        self.__nodes = nodes

    def parse_links(self, links: list):
        # Single link parse
        result = []
        for link in links:
            link = link.replace("\r", "")
            node = None
            if link[:5] == "ss://":
                # Shadowsocks
                cfg = None
                try:
                    pssip002 = ParserShadowsocksSIP002()
                    cfg = pssip002.parse_single_link(link)
                except ValueError:
                    pssb = ParserShadowsocksBasic()
                    cfg = pssb.parse_single_link(link)
                if cfg:
                    node = NodeShadowsocks(cfg)
                else:
                    logger.warn(f"Invalid shadowsocks link {link}")

            elif link[:6] == "ssr://":
                # ShadowsocksR
                pssr = ParserShadowsocksR()
                cfg = pssr.parse_single_link(link)
                if cfg:
                    node = NodeShadowsocksR(cfg)
                else:
                    logger.warn(f"Invalid shadowsocksR link {link}")

            elif link[:8] == "vmess://":
                # Vmess link (V2RayN format)
                cfg = None
                logger.info("Try V2RayN Parser.")
                pv2rn = ParserVmess()
                try:
                    cfg = pv2rn.parse_subs_config(link)
                except ValueError:
                    pass
                if not cfg:
                    logger.error(f"Invalid vmess link: {link}")
                else:
                    node = NodeV2Ray(cfg)
            elif link[:9] == "trojan://":
                cfg = None
                logger.info("Try Trojan Parser.")
                pv_trojan = TrojanParser()
                try:
                    cfg = pv_trojan.parse_link(link)
                except ValueError:
                    pass
                if cfg:
                    node = NodeTrojan(cfg)
            else:
                logger.warn(f"Unsupport link: {link}")

            if node:
                result.append(node)

        return result

    def __parse_clash(self, clash_cfg: str) -> list:
        result = []
        pc = ParserClash()
        pc.parse_config(clash_cfg)
        cfgs = pc.config_list
        for cfg in cfgs:
            if cfg["type"] == "ss":
                result.append(NodeShadowsocks(cfg["config"]))
            elif cfg["type"] == "vmess":
                result.append(NodeV2Ray(cfg["config"]))
            elif cfg["type"] == "trojan":
                result.append(NodeTrojan(cfg["config"]))

        return result

    def filter_nodes(self, fk=[], fgk=[], frk=[], ek=[], egk=[], erk=[]):
        nf = NodeFilter()
        self.__nodes = nf.filter_node(self.__nodes, fk, fgk, frk, ek, egk, erk)

    def print_nodes(self):
        for item in self.nodes:
            logger.info(
                "{} - {}".format(
                    item.config["group"],
                    item.config["remarks"]
                )
            )

    def read_subscription(self, urls: list):
        current_group = None
        for url in urls:
            if not url:
                continue

            marker_group = self.__parse_group_marker(url)
            if marker_group is not None:
                current_group = marker_group
                logger.debug(f"Using local group marker: {current_group}")
                continue

            if self.__is_proxy_link(url):
                parsed_nodes = self.parse_links([url])
                if current_group:
                    for node in parsed_nodes:
                        node.update_config({"group": current_group})
                self.__nodes.extend(parsed_nodes)
                continue

            if not self.__is_subscription_url(url):
                logger.warning("Skipping unsupported subscription entry: %s", url)
                continue

            header = {
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36"
            }
            logger.info("Reading {}".format(url))

            if PROXY_SETTINGS["enabled"]:
                auth = ""
                if PROXY_SETTINGS["username"]:
                    auth = "{}:{}@".format(
                        PROXY_SETTINGS["username"],
                        PROXY_SETTINGS["password"]
                    )
                proxy = "socks5://{}{}:{}".format(
                    auth,
                    PROXY_SETTINGS["address"],
                    PROXY_SETTINGS["port"]
                )
                proxies = {
                    "http": proxy,
                    "https": proxy
                }
                logger.info("Reading subscription via {}".format(proxy))
                rep = requests.get(url, headers=header, timeout=15, proxies=proxies)
            else:
                rep = requests.get(url, headers=header, timeout=15)
            rep.encoding = "utf-8"
            rep = rep.text

            parsed = False
            # Try base64 decode
            try:
                rep = rep.strip()
                links = (b64plus.decode(rep).decode("utf-8")).split("\n")
                logger.debug("Base64 decode success.")
                parsed_nodes = self.parse_links(links)
                if current_group:
                    for node in parsed_nodes:
                        node.update_config({"group": current_group})
                self.__nodes.extend(parsed_nodes)
                parsed = True
            except ValueError:
                logger.info("Base64 decode failed.")
            if parsed:
                continue

            # Try Clash Parser
            self.__nodes.extend(self.__parse_clash(rep))
