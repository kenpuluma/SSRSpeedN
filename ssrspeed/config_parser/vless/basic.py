# -*- coding: utf-8 -*-

from urllib.parse import unquote, parse_qsl
import re
import logging

logger = logging.getLogger("Sub")


class ParserVless:
    def __init__(self):
        pass

    @staticmethod
    def __get_base_config():
        return {
            "server": "",
            "server_port": -1,
            "id": "",
            "security": "",
            "network": "",
            "path": "",
            "host": "",
            "sni": "",
            "flow": "",
            "fingerprint": "",
            "public_key": "",
            "short_id": "",
            "spider_x": "",
            "service_name": "",
            "alpn": [],
            "allowInsecure": False,
            "remarks": "",
            "group": "N/A"
        }

    def parse_link(self, link: str):
        if not link.startswith("vless://"):
            logger.error("Unsupport link: {}".format(link))
            return None

        def percent_decode(s):
            try:
                s = unquote(s, encoding="gb2312", errors="strict")
            except:
                try:
                    s = unquote(s, encoding="utf8", errors="strict")
                except:
                    pass
            return s

        link = link[len("vless://"):]
        if not link:
            return None

        result = self.__get_base_config()

        link = percent_decode(link)
        if "#" in link:
            link, result["remarks"] = link.split("#", 1)
            result["remarks"] = re.sub(r"\s|\n", "", result["remarks"])

        uuid = ""
        host_and_query = link
        if "@" in link:
            uuid, host_and_query = link.split("@", 1)
        result["id"] = uuid

        host = host_and_query
        query = ""
        if "?" in host_and_query:
            host, query = host_and_query.split("?", 1)
        if ":" not in host:
            logger.error("Invalid vless link (missing host/port): {}".format(link))
            return None
        result["server"], result["server_port"] = host.split(":", 1)
        result["server_port"] = int(re.match(r"^\d+", result["server_port"]).group(0))

        if not result["remarks"]:
            result["remarks"] = result["server"]

        def _is_true(value):
            return str(value).lower() in ("1", "true", "yes", "y", "on")

        if query:
            link_args = dict(parse_qsl(query, keep_blank_values=True))
            result["security"] = link_args.get("security", "none")
            network = link_args.get("type", "")
            if network in ("tcp", "ws", "grpc", "h2", "http", "xhttp"):
                result["network"] = network
            result["sni"] = link_args.get("sni", "") or link_args.get("servername", "")
            result["host"] = link_args.get("host", "")
            result["path"] = link_args.get("path", "")
            result["flow"] = link_args.get("flow", "")
            result["fingerprint"] = link_args.get("fp", "") or link_args.get("fingerprint", "")
            result["public_key"] = link_args.get("pbk", "")
            result["short_id"] = link_args.get("sid", "")
            result["spider_x"] = link_args.get("spx", "")
            result["service_name"] = link_args.get("serviceName", "")
            result["group"] = link_args.get("group", "N/A")
            result["allowInsecure"] = (
                _is_true(link_args.get("allowInsecure", "0"))
                or _is_true(link_args.get("allow_insecure", "0"))
            )
            if link_args.get("alpn"):
                result["alpn"] = [a.strip() for a in link_args["alpn"].split(",") if a.strip()]

        return result
