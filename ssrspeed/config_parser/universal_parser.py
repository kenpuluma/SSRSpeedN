# -*- coding: utf-8 -*-

from copy import deepcopy
import json
import logging
import os
import requests
import re
import yaml
from urllib.parse import urlparse

from ..utils import b64plus
from ..types.nodes import NodeMihomo, NodeShadowsocks, NodeShadowsocksR, NodeV2Ray, NodeTrojan, NodeVLESS
from .ss import ParserShadowsocksBasic, ParserShadowsocksSIP002
from .ssr import ParserShadowsocksR
from .vmess import ParserVmess
from .node_filter import NodeFilter
from .trojan import TrojanParser
from .vless import ParserVless

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
            line.startswith("trojan://") or
            line.startswith("vless://")
        )

    @staticmethod
    def __is_subscription_url(line: str) -> bool:
        try:
            parsed = urlparse(line.strip())
        except ValueError:
            return False
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)

    @staticmethod
    def __coerce_port(value):
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def __normalize_provider_path(base_dir: str, rel_path: str) -> str:
        return os.path.normpath(os.path.join(base_dir, rel_path.replace("/", os.sep)))

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
            elif _type == "Trojan":
                result.append(NodeTrojan(config["config"]))
            elif _type == "VLESS":
                result.append(NodeVLESS(config["config"]))
            elif _type == "Mihomo":
                result.append(NodeMihomo(config["config"]))
            else:
                logger.warning(f"Unknown node type: {_type}")
        return result

    @property
    def nodes(self):
        return deepcopy(self.__nodes)

    def __clean_nodes(self):
        self.__nodes.clear()

    def set_nodes(self, nodes: list):
        self.__clean_nodes()
        self.__nodes = nodes

    def __build_mihomo_node(self, proxy_cfg: dict, forced_group: str = None):
        if not isinstance(proxy_cfg, dict):
            logger.warning("Skip invalid Clash proxy entry: %s", proxy_cfg)
            return None

        proxy_copy = deepcopy(proxy_cfg)
        remarks = proxy_copy.get("name", proxy_copy.get("remarks", "proxy"))
        server = proxy_copy.get("server", "")
        server_port = self.__coerce_port(proxy_copy.get("port", proxy_copy.get("server_port", 0)))
        if not server or not server_port:
            logger.warning("Skip Clash proxy without server/port: %s", remarks)
            return None

        group = forced_group or proxy_copy.get("group") or proxy_copy.get("peer") or "N/A"
        return NodeMihomo({
            "group": group,
            "remarks": remarks,
            "server": server,
            "server_port": server_port,
            "raw_proxy": proxy_copy
        })

    def parse_links(self, links: list):
        result = []
        for link in links:
            link = link.replace("\r", "")
            if not link:
                continue
            node = None
            if link[:5] == "ss://":
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
                    logger.warning(f"Invalid shadowsocks link {link}")

            elif link[:6] == "ssr://":
                pssr = ParserShadowsocksR()
                cfg = pssr.parse_single_link(link)
                if cfg:
                    node = NodeShadowsocksR(cfg)
                else:
                    logger.warning(f"Invalid shadowsocksR link {link}")

            elif link[:8] == "vmess://":
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
            elif link[:8] == "vless://":
                cfg = None
                logger.info("Try VLESS Parser.")
                pv_vless = ParserVless()
                try:
                    cfg = pv_vless.parse_link(link)
                except ValueError:
                    pass
                if cfg:
                    node = NodeVLESS(cfg)
                else:
                    logger.warning(f"Invalid vless link {link}")
            else:
                logger.warning(f"Unsupport link: {link}")

            if node:
                result.append(node)

        return result

    def __parse_clash(self, clash_cfg: str, forced_group: str = None) -> list:
        result = []
        try:
            parsed = yaml.load(clash_cfg, Loader=yaml.FullLoader)
        except Exception:
            return result

        proxies = parsed.get("proxies") if isinstance(parsed, dict) else None
        if not isinstance(proxies, list):
            return result

        for proxy_cfg in proxies:
            node = self.__build_mihomo_node(proxy_cfg, forced_group=forced_group)
            if node:
                result.append(node)
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

    def __append_nodes_with_group(self, nodes: list, group: str = None):
        if group:
            for node in nodes:
                node.update_config({"group": group})
        self.__nodes.extend(nodes)

    def __read_remote_subscription(self, url: str, forced_group: str = None):
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
        rep = rep.text.strip()

        try:
            links = b64plus.decode(rep).decode("utf-8").split("\n")
            logger.debug("Base64 decode success.")
            self.__append_nodes_with_group(self.parse_links(links), forced_group)
            return
        except ValueError:
            logger.info("Base64 decode failed.")

        plain_links = [line for line in re.split(r'\r\n|\r|\n', rep) if self.__is_proxy_link(line)]
        if plain_links:
            self.__append_nodes_with_group(self.parse_links(plain_links), forced_group)
            return

        clash_nodes = self.__parse_clash(rep, forced_group=forced_group)
        if clash_nodes:
            self.__nodes.extend(clash_nodes)

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
                self.__append_nodes_with_group(self.parse_links([url]), current_group)
                continue

            if not self.__is_subscription_url(url):
                logger.warning("Skipping unsupported subscription entry: %s", url)
                continue

            self.__read_remote_subscription(url, forced_group=current_group)

    def read_manifest(self, manifest: dict, base_dir: str):
        providers = manifest.get("providers", [])
        if not isinstance(providers, list):
            logger.warning("Invalid providers manifest: missing providers array")
            return

        for provider in providers:
            if not provider.get("enabled", True):
                continue

            group = provider.get("name", "N/A")
            rel_path = provider.get("file", "")
            fmt = str(provider.get("format", "")).lower()
            if not rel_path:
                logger.warning("Skipping provider %s without file path", group)
                continue

            provider_path = self.__normalize_provider_path(base_dir, rel_path)
            try:
                with open(provider_path, "r", encoding="utf-8") as f:
                    raw = f.read()
            except FileNotFoundError:
                logger.warning("Provider file not found: %s", provider_path)
                continue

            if fmt == "clash":
                self.__nodes.extend(self.__parse_clash(raw, forced_group=group))
                continue

            if fmt == "links":
                self.__append_nodes_with_group(self.parse_links(re.split(r'\r\n|\r|\n', raw)), group)
                continue

            clash_nodes = self.__parse_clash(raw, forced_group=group)
            if clash_nodes:
                self.__nodes.extend(clash_nodes)
                continue

            self.__append_nodes_with_group(self.parse_links(re.split(r'\r\n|\r|\n', raw)), group)

    def read_subscription_file(self, filename: str):
        with open(filename, "r", encoding="utf-8") as f:
            raw_data = f.read()

        try:
            manifest = json.loads(raw_data)
            if isinstance(manifest, dict) and isinstance(manifest.get("providers"), list):
                self.read_manifest(manifest, os.path.dirname(filename))
                return
        except ValueError:
            pass

        clash_nodes = self.__parse_clash(raw_data)
        if clash_nodes:
            self.__nodes.extend(clash_nodes)
            return

        self.read_subscription(re.split(r'\r\n|\r|\n', raw_data))
