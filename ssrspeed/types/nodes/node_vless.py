# -*- coding: utf-8 -*-

from .node_type_base import BaseNode

class NodeVLESS(BaseNode):
	def __init__(self, config: dict):
		super(NodeVLESS, self).__init__(config)
		self._type = "VLESS"
