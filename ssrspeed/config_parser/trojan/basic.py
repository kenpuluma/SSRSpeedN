# -*- coding: utf-8 -*-

from urllib.parse import quote, unquote, parse_qsl
from base64 import urlsafe_b64decode, urlsafe_b64encode
import re
import logging

logger = logging.getLogger("Sub")


class TrojanParser:
    def __init__(self):
        pass

    @staticmethod
    def __get_base_config():
        return {
            "server": "",
            "server_port": -1,
            "password": "",
            "sni": "",
            "skip-cert-verify": False,
            "network": "",
            "path": "",
            "host": "",
            "ws-path": "",
            "ws-headers": {},
            "remarks": "",
            "group": "N/A"
        }

    def parse_link(self, link: str):
        if not link.startswith("trojan://"):
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

        link = link[len("trojan://"):]
        if not link:
            return None

        result = self.__get_base_config()

        link = percent_decode(link)
        if "#" in link:
            link, result["remarks"] = link.split("#", 1)
            result["remarks"] = re.sub(r"\s|\n", "", result["remarks"])

        password = ""
        host_and_query = link
        if "@" in link:
            password, host_and_query = link.split("@", 1)
        result["password"] = password

        host = host_and_query
        query = ""
        if "?" in host_and_query:
            host, query = host_and_query.split("?", 1)
        if ":" not in host:
            logger.error("Invalid trojan link (missing host/port): {}".format(link))
            return None
        result["server"], result["server_port"] = host.split(":", 1)
        result["server_port"] = int(re.match(r"^\d+", result["server_port"]).group(0))

        if not result["remarks"]:
            result["remarks"] = result["server"]

        def _is_true(value):
            return str(value).lower() in ("1", "true", "yes", "y", "on")

        if query:
            link_args = dict(parse_qsl(query, keep_blank_values=True))
            if "skip-cert-verify" in link_args:
                result["skip-cert-verify"] = _is_true(link_args.get("skip-cert-verify"))
            elif "allowinsecure" in link_args:
                result["skip-cert-verify"] = _is_true(link_args.get("allowinsecure"))
            elif "allowInsecure" in link_args:
                result["skip-cert-verify"] = _is_true(link_args.get("allowInsecure"))
            result["sni"] = link_args.get("sni", "") or link_args.get("peer", "")
            result["group"] = link_args.get("group", link_args.get("peer", "N/A"))

            network = link_args.get("type", "")
            if network in ("ws", "grpc", "h2", "tcp"):
                result["network"] = network

            if link_args.get("path"):
                result["path"] = link_args["path"]
                if network == "ws":
                    result["ws-path"] = link_args["path"]
            if link_args.get("host"):
                result["host"] = link_args["host"]
                if network == "ws":
                    result["ws-headers"] = {"Host": link_args["host"]}
        return result
