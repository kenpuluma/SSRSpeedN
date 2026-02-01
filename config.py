#coding:utf-8

import os
import json

__version__ = "1.04"
__web_api_version__ = "0.5.2"

config = {
	"VERSION": __version__,
	"WEB_API_VERSION": __web_api_version__
}

LOADED = False

if not LOADED:
	if not os.path.exists("ssrspeed_config.json") or os.path.isdir("ssrspeed_config.json"):
		raise FileNotFoundError("Configuration file 'ssrspeed_config.json' not found. Please create one based on the example in the repository.")

	with open("ssrspeed_config.json", "r", encoding = "utf-8") as f:
		file_config = json.load(f)
		config.update(file_config)
	LOADED = True

