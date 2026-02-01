#coding:utf-8

import logging
import sys
import os
import subprocess

from .platform_check import check_platform

logger = logging.getLogger("Sub")

class RequirementsCheck(object):
	def __init__(self):
		self.__winRequire = {
			"Mihomo":[
				"./clients/mihomo/mihomo.exe"
			]
		}

		self.__linuxRequire = {
			"Mihomo":[
				"./clients/mihomo/mihomo"
			]
		}

	def check(self):
		pfInfo = check_platform()
		if (pfInfo == "Windows"):
			self.__checks(self.__winRequire)
		elif (pfInfo == "Linux" or pfInfo == "MacOS"):
			self.__linuxCheck()
		else:
			logger.critical("Unsupport platform !")
			sys.exit(1)

	def __checks(self,requires = {}):
		for key in requires.keys():
			for require in requires[key]:
				logger.info("Checking {}".format(require))
				if (os.path.exists(require)):
					if (os.path.isdir(require)):
						logger.warn("Requirement {} not found !!!".format(require))
						continue
				else:
					logger.warn("Requirement {} not found !!!".format(require))

	def __linuxCheck(self):
		self.__checks(self.__linuxRequire)


