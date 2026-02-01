#coding:utf-8

import time
import sys
import os
import io
import logging, colorlog

from config import config

from ssrspeed.shell import cli as cli_cfg
from ssrspeed.utils import check_platform, RequirementsCheck
from ssrspeed.core import SSRSpeedCore


def _force_utf8(stream_name):
	stream = getattr(sys, stream_name, None)
	if not stream:
		return
	encoding = (getattr(stream, "encoding", None) or "").lower()
	if encoding == "utf-8":
		return
	try:
		stream.reconfigure(encoding="utf-8", errors="backslashreplace")
		return
	except Exception:
		pass
	buffer = getattr(stream, "buffer", None)
	if buffer:
		setattr(sys, stream_name, io.TextIOWrapper(buffer, encoding="utf-8", errors="backslashreplace"))


_force_utf8("stdout")
_force_utf8("stderr")
if (not os.path.exists("./logs/")):
	os.mkdir("./logs/")
if (not os.path.exists("./results/")):
	os.mkdir("./results/")

loggerList = []
loggerSub = logging.getLogger("Sub")
logger = logging.getLogger(__name__)
loggerList.append(loggerSub)
loggerList.append(logger)

formatter = logging.Formatter("[%(asctime)s][%(levelname)s][%(thread)d][%(filename)s:%(lineno)d]%(message)s")
fileHandler = logging.FileHandler("./logs/" + time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()) + ".log",encoding="utf-8")
fileHandler.setFormatter(formatter)
consoleHandler = colorlog.ConsoleHandler()
consoleHandler.setFormatter(formatter)

VERSION = config["VERSION"]

if (__name__ == "__main__"):
	pfInfo = check_platform()
	if (pfInfo == "Unknown"):
		logger.critical("Your system does not supported. Please contact developer.")
		sys.exit(1)

	CONFIG_LOAD_MODE = 0  # 0 for import result, 1 for guiconfig, 2 for subscription url, 3 for url file
	CONFIG_FILENAME = ""
	CONFIG_URL = ""
	CONFIG_URL_FILENAME = ""
	IMPORT_FILENAME = ""
	FILTER_KEYWORD = []
	FILTER_GROUP_KEYWORD = []
	FILTER_REMARK_KEYWORD = []
	EXCLUDE_KEYWORD = []
	EXCLUDE_GROUP_KEYWORD = []
	EXCLUDE_REMARK_KEYWORD = []
	SORT_METHOD = ""
	RESULT_IMAGE_COLOR = "origin"
	
	options, args = cli_cfg.init(VERSION)

	print("****** SSRSpeedN Connectivity Test ******")
	print("Mihomo delay + Streaming + NAT detection")
	print("*****************************************")

	if (options.debug):
		for item in loggerList:
			item.setLevel(logging.DEBUG)
			item.addHandler(fileHandler)
			item.addHandler(consoleHandler)
	else:
		for item in loggerList:
			item.setLevel(logging.INFO)
			item.addHandler(fileHandler)
			item.addHandler(consoleHandler)

	logger.info("SSRSpeed N v{}".format(config["VERSION"]))

	if (logger.level == logging.DEBUG):
		logger.debug("Program running in debug mode")

	if not options.skip_requirements_check:
		rc = RequirementsCheck()
		rc.check()
	else:
		logger.warn("Requirements check skipped.")

	if (options.result_color):
		RESULT_IMAGE_COLOR = options.result_color

	if (options.import_file):
		CONFIG_LOAD_MODE = 0
	elif (options.guiConfig):
		CONFIG_LOAD_MODE = 1
		CONFIG_FILENAME = options.guiConfig
	elif(options.url):
		CONFIG_LOAD_MODE = 2
		CONFIG_URL = options.url
	elif (options.url_filename):
		CONFIG_LOAD_MODE = 3
		CONFIG_URL_FILENAME = options.url_filename
	else:
		logger.error("No config input, exiting...")
		sys.exit(1)

	if (options.filter):
		FILTER_KEYWORD = options.filter
	if (options.group):
		FILTER_GROUP_KEYWORD = options.group
	if (options.remarks):
		FILTER_REMARK_KEYWORD = options.remarks

	if (options.efliter):
		EXCLUDE_KEYWORD = options.efliter
	if (options.egfilter):
		EXCLUDE_GROUP_KEYWORD = options.egfilter
	if (options.erfilter):
		EXCLUDE_REMARK_KEYWORD = options.erfilter

	logger.debug(
		"\nFilter keyword: %s\nFilter group: %s\nFilter remark: %s\nExclude keyword: %s\nExclude group: %s\nExclude remark: %s" % (
			str(FILTER_KEYWORD), str(FILTER_GROUP_KEYWORD), str(FILTER_REMARK_KEYWORD),
			str(EXCLUDE_KEYWORD), str(EXCLUDE_GROUP_KEYWORD), str(EXCLUDE_REMARK_KEYWORD)
		)
	)
	
	if (options.sort_method):
		sm = options.sort_method
		if (sm == "ping"):
			SORT_METHOD = "PING"
		elif(sm == "rping"):
			SORT_METHOD = "REVERSE_PING"
		else:
			logger.error("Sort method %s not supported. Use 'ping' or 'rping'." % sm)

	sc = SSRSpeedCore()

	if (options.import_file and CONFIG_LOAD_MODE == 0):
		IMPORT_FILENAME = options.import_file
		sc.colors = RESULT_IMAGE_COLOR
		sc.sortMethod = SORT_METHOD if SORT_METHOD else ""
		sc.import_and_export(IMPORT_FILENAME)
		sys.exit(0)

	if (CONFIG_LOAD_MODE == 1):
		sc.console_setup(
			RESULT_IMAGE_COLOR,
			SORT_METHOD,
			cfg_filename=CONFIG_FILENAME
		)
	elif (CONFIG_LOAD_MODE == 3):
		sc.console_setup(
			RESULT_IMAGE_COLOR,
			SORT_METHOD,
			url_filename=CONFIG_URL_FILENAME
		)
	else:
		sc.console_setup(
			RESULT_IMAGE_COLOR,
			SORT_METHOD,
			url=CONFIG_URL
		)

	if options.group_override:
		sc.set_group(options.group_override)

	sc.filter_nodes(
		FILTER_KEYWORD,
		FILTER_GROUP_KEYWORD,
		FILTER_REMARK_KEYWORD,
		EXCLUDE_KEYWORD,
		EXCLUDE_GROUP_KEYWORD,
		EXCLUDE_REMARK_KEYWORD
	)
	sc.clean_result()
	
	sc.start_test()
