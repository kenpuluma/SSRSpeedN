#coding:utf-8

import logging
import sys
from optparse import OptionParser

logger = logging.getLogger("Sub")

def setArgsListCallback(option,opt_str,value,parser):
	assert value is None
	value = []
	def floatable(arg):
		try:
			float(arg)
			return True
		except ValueError:
			return False
	for arg in parser.rargs:
		if (arg[:2] == "--" and len(arg) > 2):
			break
		if (arg[:1] == "-" and len(arg) > 1 and not floatable(arg)):
			break
		if (arg.replace(" ","") == ""):
			continue
		value.append(arg)
	del parser.rargs[:len(value)]
	setattr(parser.values,option.dest,value)

def setOpts(parser):
	parser.add_option(
		"-u","--url",
		action="store",
		dest="url",
		default="",
		help="Load ssr config from subscription url."
		)
	parser.add_option(
		"--url-file",
		action="store",
		dest="url_filename",
		default="",
		help="Load ssr config from subscription file."
		)
	parser.add_option(
		"--include",
		action="callback",
		callback = setArgsListCallback,
		dest="filter",
		default = [],
		help="Filter nodes by group and remarks using keyword."
		)
	parser.add_option(
		"--include-remark",
		action="callback",
		callback = setArgsListCallback,
		dest="remarks",
		default=[],
		help="Filter nodes by remarks using keyword."
		)
	parser.add_option(
		"--include-group",
		action="callback",
		callback = setArgsListCallback,
		dest="group",
		default=[],
		help="Filter nodes by group name using keyword."
		)
	parser.add_option(
		"--exclude",
		action="callback",
		callback = setArgsListCallback,
		dest="efliter",
		default = [],
		help="Exclude nodes by group and remarks using keyword."
		)
	parser.add_option(
		"--exclude-group",
		action="callback",
		callback = setArgsListCallback,
		dest="egfilter",
		default=[],
		help="Exclude nodes by group using keyword."
		)
	parser.add_option(
		"--exclude-remark",
		action="callback",
		callback = setArgsListCallback,
		dest="erfilter",
		default = [],
		help="Exclude nodes by remarks using keyword."
	)
	parser.add_option(
		"--debug",
		action="store_true",
		dest="debug",
		default=False,
		help="Run program in debug mode."
		)

def init(VERSION):
	parser = OptionParser(usage="Usage: %prog [options] arg1 arg2...",version="SSR Speed Tool " + VERSION)
	setOpts(parser)
	if (len(sys.argv) == 1):
		parser.print_help()
		sys.exit(0)
	(options,args) = parser.parse_args()
	return (options,args)
