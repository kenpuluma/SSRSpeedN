# -*- coding: utf-8 -*-

import logging
import json

from ...utils import b64plus

logger = logging.getLogger("Sub")


class ParserVmess:
    def __init__(self):
        self.__decoded_configs = []

    @staticmethod
    def __get_base_config():
        return {
            "server": "",
            "server_port": -1,
            "id": "",
            "alterId": 0,
            "security": "",
            "type": "",
            "path": "",
            "network": "",
            "allowInsecure": False,
            "headers": {},
            "tls-host": "",
            "host": "",
            "tls": "",
            "remarks": "",
            "group": "N/A"
        }

    def parse_subs_config(self, raw_link):
        link = raw_link[8:]
        link_decoded = b64plus.decode(link).decode("utf-8")
        try:
            _conf = json.loads(link_decoded)
        except json.JSONDecodeError:
            return None
        try:
            _config = self.__get_base_config()
            cfg_version = str(_conf.get("v", "1"))
            server = _conf["add"]
            port = int(_conf["port"])
            _type = _conf.get("type", "none")  # Obfs type
            uuid = _conf["id"]
            aid = int(_conf.get("aid", 0))
            net = _conf["net"]
            group = _conf.get("group", "N/A")
            path = ""
            host = ""
            if cfg_version == "2":
                host = _conf.get("host", "")  # http host, websocket host, h2 host, quic encrypt method
                path = _conf.get("path", "")  # Websocket path, http path, quic encrypt key
            # V2RayN Version 1 Share Link Support
            else:
                try:
                    host = _conf.get("host", ";").split(";")[0]
                    path = _conf.get("host", ";").split(";")[1]
                except IndexError:
                    pass
            tls = _conf.get("tls", "none")  # TLS
            tls_host = host
            security = _conf.get("security", "auto")
            remarks = _conf.get("ps", server)
            remarks = remarks if remarks else server
            logger.debug(
                "Server : {},Port : {}, tls-host : {}, Path : {},Type : {},UUID : {},"
                "AlterId : {},Network : {},Host : {},TLS : {},Remarks : {},group={}".format(
                    server, port, tls_host, path, _type, uuid,
                    aid, net, host, tls, remarks, group
                )
            )
            _config["remarks"] = remarks
            _config["group"] = group
            _config["server"] = server
            _config["server_port"] = port
            _config["id"] = uuid
            _config["alterId"] = aid
            _config["security"] = security
            _config["type"] = _type
            _config["path"] = path
            _config["network"] = net
            _config["tls-host"] = tls_host
            _config["host"] = host
            _config["tls"] = tls
            return _config
        except:
            logger.exception("Parse {} failed.(V2RayN Method)".format(raw_link))
            return None
