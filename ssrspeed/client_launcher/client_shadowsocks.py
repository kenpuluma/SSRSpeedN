# coding:utf-8

import json
import subprocess
import os
import sys
import logging

logger = logging.getLogger("Sub")

from .base_client import BaseClient


class Shadowsocks(BaseClient):
    def __init__(self):
        super(Shadowsocks, self).__init__()

    def _filter_config_for_rust(self, config):
        """Filter config to only include fields supported by shadowsocks-rust.
        Removes SSR-specific fields while keeping core shadowsocks settings.
        """
        # Fields supported by shadowsocks-rust
        allowed_fields = {
            "server",
            "server_port",
            "local_address",
            "local_port",
            "password",
            "method",
            "timeout"
        }

        # Create filtered config with only allowed fields
        filtered = {k: v for k, v in config.items() if k in allowed_fields}

        # Add plugin fields only if they're actually being used
        if config.get("plugin") and config["plugin"].strip():
            filtered["plugin"] = config["plugin"]
            if config.get("plugin_opts") and config["plugin_opts"].strip():
                filtered["plugin_opts"] = config["plugin_opts"]

        return filtered

    def startClient(self, config={}, testing=False):
        self._config = config
        #	self._config["server_port"] = int(self._config["server_port"])
        filtered_config = self._filter_config_for_rust(self._config)
        with open("./config.json", "w+", encoding="utf-8") as f:
            f.write(json.dumps(filtered_config, indent=2))
        if (self._process == None):
            if (self._checkPlatform() == "Windows"):
                if (logger.level == logging.DEBUG):
                    self._process = subprocess.Popen(
                        ["./clients/shadowsocks-rust/sslocal.exe", "-c", "{}/config.json".format(os.getcwd())])
                else:
                    self._process = subprocess.Popen(
                        ["./clients/shadowsocks-rust/sslocal.exe", "-c", "{}/config.json".format(os.getcwd())],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info("Starting Shadowsocks-Rust with server %s:%d" % (config["server"], config["server_port"]))
            elif (self._checkPlatform() == "Linux" or self._checkPlatform() == "MacOS"):
                if (logger.level == logging.DEBUG):
                    self._process = subprocess.Popen(["sslocal", "-c", "%s/config.json" % os.getcwd()])
                else:
                    self._process = subprocess.Popen(["sslocal", "-c", "%s/config.json" % os.getcwd()],
                                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info("Starting Shadowsocks-Rust with server %s:%d" % (config["server"], config["server_port"]))
            else:
                logger.critical("Your system does not supported.Please contact developer.")
                sys.exit(1)
