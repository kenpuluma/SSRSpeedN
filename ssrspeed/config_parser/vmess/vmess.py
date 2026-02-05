# -*- coding: utf-8 -*-

import logging
import json

from ...utils import b64plus

logger = logging.getLogger("Sub")


class ParserVmess:
    def __init__(self):
        self.__decoded_configs = []

    def parse_subs_config(self, raw_link):
        link = raw_link[8:]
        link_decoded = b64plus.decode(link).decode("utf-8")
        try:
            _conf = json.loads(link_decoded)
        except json.JSONDecodeError:
            return None
        try:
            cfg_version = str(_conf.get("v", "1"))
            server = _conf["add"]
            port = int(_conf["port"])
            _type = _conf.get("type", "none")  # Obfs type
            uuid = _conf["id"]
            aid = int(_conf["aid"])
            net = _conf["net"]
            group = "N/A"
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
            _config = {
                "remarks": remarks,
                "server": server,
                "server_port": port,
                "id": uuid,
                "alterId": aid,
                "security": security,
                "type": _type,
                "path": path,
                "network": net,
                "tls-host": tls_host,
                "host": host,
                "tls": tls
            }
            return _config
        except:
            logger.exception("Parse {} failed.(V2RayN Method)".format(raw_link))
            return None
