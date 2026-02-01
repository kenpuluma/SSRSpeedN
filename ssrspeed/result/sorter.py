#coding:utf-8

class Sorter(object):
	def __sortByPing(self, result):
		# Return a high value for nodes with 0 ping (timeout) so they sort to the end
		ping = result.get("ping", 0)
		return ping if ping > 0 else 999999

	def sortResult(self, result, sortMethod):
		if sortMethod:
			if sortMethod == "PING":
				result.sort(key=self.__sortByPing)
			elif sortMethod == "REVERSE_PING":
				result.sort(key=self.__sortByPing, reverse=True)
		return result
