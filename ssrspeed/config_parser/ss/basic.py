# -*- coding: utf-8 -*-

import logging
import binascii

from ...utils import b64plus

logger = logging.getLogger("Sub")


class ParserShadowsocksBasic:
    def __init__(self):
        self.__config_list = []

    @staticmethod
    def __get_base_config():
        return {
            "server": "",
            "server_port": -1,
            "method": "",
            "password": "",
            "plugin": "",
            "plugin_opts": "",
            "plugin_args": "",
            "remarks": "",
            "group": "N/A"
        }

    def __parse_link(self, link):
        _config = self.__get_base_config()

        if link[:5] != "ss://":
            logger.error("Unsupport link : %s" % link)
            return None

        try:
            decoded = b64plus.decode(link[5:]).decode("utf-8")
            at_pos = decoded.rfind("@")
            if at_pos == -1:
                raise ValueError("Not shadowsocks basic link.")
            mp = decoded[:at_pos]
            ap = decoded[at_pos + 1:]
            mp_pos = mp.find(":")
            ap_pos = ap.find(":")
            if mp_pos == -1 or ap_pos == -1:
                raise ValueError("Not shadowsocks basic link.")
            encryption = mp[:mp_pos]
            password = mp[mp_pos + 1:]
            server = ap[:ap_pos]
            port = int(ap[ap_pos + 1:])
            _config["server"] = server
            _config["server_port"] = port
            _config["method"] = encryption
            _config["password"] = password
            _config["remarks"] = _config["server"]
        except binascii.Error:
            raise ValueError("Not shadowsocks basic link.")
        except:
            logger.exception(f"Exception link {link}\n")
            return None
        return _config

    def parse_single_link(self, link):
        return self.__parse_link(link)

    def parse_subs_config(self, links):
        for link in links:
            link = link.strip()
            cfg = self.__parse_link(link)
            if cfg:
                self.__config_list.append(cfg)
        logger.info("Read {} config(s).".format(len(self.__config_list)))
        return self.__config_list
