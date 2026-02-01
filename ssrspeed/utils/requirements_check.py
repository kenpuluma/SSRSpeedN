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
				"mihomo"
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
		self.__linuxCheckMihomo()	

	def __linuxCheckMihomo(self):
		"""Check if Mihomo is available in PATH"""
		mihomo_found = False
		for cmdpath in os.environ["PATH"].split(":"):
			if (not os.path.isdir(cmdpath)):
				continue
			for filename in os.listdir(cmdpath):
				if (filename == "mihomo"):
					logger.info("Mihomo found {}".format(os.path.join(cmdpath,"mihomo")))
					mihomo_found = True
					break
			if mihomo_found:
				break
		if (not mihomo_found):
			logger.warn("Mihomo not found in PATH !!!")
		return mihomo_found


