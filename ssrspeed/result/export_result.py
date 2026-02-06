#coding:utf-8

from PIL import Image, ImageDraw, ImageFont
import json
import os
import time
import logging

logger = logging.getLogger("Sub")

from config import config


class ExportResult(object):
	def __init__(self):
		self.__config = config["exportResult"]
		self.__hide_ntt = not config["ntt"]["enabled"]
		self.__hide_netflix = not config["netflix"]
		self.__hide_bilibili = not config["bilibili"]
		self.__hide_stream = not config["stream"]
		self.__hide_ping = not config["ping"]
		self.__hide_port = not config["port"]
		self.__font = ImageFont.truetype(self.__config["font"], 18)
		self.__timeUsed = "N/A"

	def setTimeUsed(self, timeUsed):
		self.__timeUsed = time.strftime("%H:%M:%S", time.gmtime(timeUsed))
		logger.info("Time Used : {}".format(self.__timeUsed))

	def export(self, result, split=0, exportType=0):
		if not exportType:
			self.__exportAsJson(result)
		self.__exportAsPng(result)

	def __getMaxWidth(self, result):
		font = self.__font
		draw = ImageDraw.Draw(Image.new("RGB", (1, 1), (255, 255, 255)))
		maxGroupWidth = 0
		maxRemarkWidth = 0
		for item in result:
			group = item["group"]
			remark = item["remarks"]
			maxGroupWidth = max(maxGroupWidth, draw.textsize(group, font=font)[0])
			maxRemarkWidth = max(maxRemarkWidth, draw.textsize(remark, font=font)[0])
		return (maxGroupWidth + 10, maxRemarkWidth + 10)

	def __getMaxWidthStream(self, result):
		maxStreamWidth = 0
		for item in result:
			netflix_type = item.get("Ntype", "None")
			hbo_type = item.get("Htype", False)
			disney_type = item.get("Dtype", False)
			youtube_type = item.get("Ytype", False)
			abema_type = item.get("Atype", False)
			bahamut_type = item.get("Btype", False)
			chatgpt_type = item.get("Ctype", False)
			bilibili_type = item.get("Bltype", "N/A")
			tvb_type = item.get("Ttype", False)
			
			n_type = netflix_type[:4] == "Full" if netflix_type else False
			bl_type = bilibili_type == "全解锁"
			
			sums = n_type + hbo_type + disney_type + youtube_type + abema_type + bahamut_type + tvb_type + bl_type + chatgpt_type
			tmpWidth = sums * 35 + 20

			if tmpWidth > maxStreamWidth:
				maxStreamWidth = tmpWidth

		return maxStreamWidth

	def __getBasePos(self, width, text):
		font = self.__font
		draw = ImageDraw.Draw(Image.new("RGB", (1, 1), (255, 255, 255)))
		textSize = draw.textsize(text, font=font)[0]
		basePos = (width - textSize) / 2
		return basePos

	def __exportAsPng(self, result):
		resultFont = self.__font
		generatedTime = time.localtime()
		imageHeight = len(result) * 30 + 30
		weight = self.__getMaxWidth(result)
		streamWeight = self.__getMaxWidthStream(result)
		groupWidth = weight[0]
		remarkWidth = weight[1]
		
		if groupWidth < 60:
			groupWidth = 60
		if remarkWidth < 90:
			remarkWidth = 90
		if streamWeight < 120:
			streamWeight = 120
		otherWidth = 100

		# Load logos
		abema_logo = Image.open("./resources/logos/abema.png")
		abema_logo.thumbnail((28, 28))
		bahamut_logo = Image.open("./resources/logos/Bahamut.png")
		bahamut_logo.thumbnail((28, 28))
		disney_logo = Image.open("./resources/logos/DisneyPlus.png")
		disney_logo.thumbnail((28, 28))
		hbo_logo = Image.open("./resources/logos/HBO.png")
		hbo_logo.thumbnail((28, 28))
		netflix_logo = Image.open("./resources/logos/Netflix.png")
		netflix_logo.thumbnail((28, 28))
		tvb_logo = Image.open("./resources/logos/tvb.png")
		tvb_logo.thumbnail((28, 28))
		youtube_logo = Image.open("./resources/logos/YouTube.png")
		youtube_logo.thumbnail((28, 28))
		bilibili_logo = Image.open("./resources/logos/bilibili.png")
		bilibili_logo.thumbnail((28, 28))
		chatgpt_logo = Image.open("./resources/logos/chatgpt.png")
		chatgpt_logo.thumbnail((28, 28))

		# Calculate column positions
		groupRightPosition = groupWidth
		remarkRightPosition = groupRightPosition + remarkWidth
		imageRightPosition = remarkRightPosition

		if not self.__hide_ping:
			imageRightPosition = remarkRightPosition + otherWidth
		pingRightPosition = imageRightPosition

		if not self.__hide_port:
			imageRightPosition = pingRightPosition + otherWidth
		portRightPosition = imageRightPosition

		if not self.__hide_ntt:
			imageRightPosition = portRightPosition + otherWidth + 80
		ntt_right_position = imageRightPosition

		if not self.__hide_netflix:
			imageRightPosition = ntt_right_position + otherWidth + 60
		netflix_right_position = imageRightPosition

		if not self.__hide_bilibili:
			imageRightPosition = netflix_right_position + otherWidth + 45
		bilibili_right_position = imageRightPosition

		if not self.__hide_stream:
			imageRightPosition = bilibili_right_position + streamWeight
		stream_right_position = imageRightPosition

		newImageHeight = imageHeight + 30 * 3
		resultImg = Image.new("RGB", (imageRightPosition, newImageHeight), (255, 255, 255))
		draw = ImageDraw.Draw(resultImg)

		# Header
		text = "SSRSpeed N ( v{} )".format(config["VERSION"])
		draw.text((self.__getBasePos(imageRightPosition, text), 4), text, font=resultFont, fill=(0, 0, 0))
		draw.line((0, 30, imageRightPosition - 1, 30), fill=(127, 127, 127), width=1)

		# Column borders
		draw.line((1, 0, 1, newImageHeight - 1), fill=(127, 127, 127), width=1)
		draw.line((groupRightPosition, 30, groupRightPosition, imageHeight + 30 - 1), fill=(127, 127, 127), width=1)
		draw.line((remarkRightPosition, 30, remarkRightPosition, imageHeight + 30 - 1), fill=(127, 127, 127), width=1)

		if not self.__hide_ping:
			draw.line((pingRightPosition, 30, pingRightPosition, imageHeight + 30 - 1), fill=(127, 127, 127), width=1)
		if not self.__hide_port:
			draw.line((portRightPosition, 30, portRightPosition, imageHeight + 30 - 1), fill=(127, 127, 127), width=1)
		if not self.__hide_ntt:
			draw.line((ntt_right_position, 30, ntt_right_position, imageHeight + 30 - 1), fill=(127, 127, 127), width=1)
		if not self.__hide_netflix:
			draw.line((netflix_right_position, 30, netflix_right_position, imageHeight + 30 - 1), fill=(127, 127, 127), width=1)
		if not self.__hide_bilibili:
			draw.line((bilibili_right_position, 30, bilibili_right_position, imageHeight + 30 - 1), fill=(127, 127, 127), width=1)
		if not self.__hide_stream:
			draw.line((stream_right_position, 30, stream_right_position, imageHeight + 30 - 1), fill=(127, 127, 127), width=1)

		draw.line((imageRightPosition, 0, imageRightPosition, newImageHeight - 1), fill=(127, 127, 127), width=1)
		draw.line((0, 0, imageRightPosition - 1, 0), fill=(127, 127, 127), width=1)

		# Column headers
		draw.text((self.__getBasePos(groupRightPosition, "Group"), 30 + 4), "Group", font=resultFont, fill=(0, 0, 0))
		draw.text((groupRightPosition + self.__getBasePos(remarkRightPosition - groupRightPosition, "Remarks"), 30 + 4), "Remarks", font=resultFont, fill=(0, 0, 0))

		if not self.__hide_ping:
			draw.text((remarkRightPosition + self.__getBasePos(pingRightPosition - remarkRightPosition, "Ping(ms)"), 30 + 4), "Ping(ms)", font=resultFont, fill=(0, 0, 0))

		if not self.__hide_port:
			draw.text((pingRightPosition + self.__getBasePos(portRightPosition - pingRightPosition, "Port"), 30 + 4), "Port", font=resultFont, fill=(0, 0, 0))

		if not self.__hide_ntt:
			draw.text((portRightPosition + self.__getBasePos(ntt_right_position - portRightPosition, "UDP NAT Type"), 30 + 4), "UDP NAT Type", font=resultFont, fill=(0, 0, 0))

		if not self.__hide_netflix:
			draw.text((ntt_right_position + self.__getBasePos(netflix_right_position - ntt_right_position, "Netflix"), 30 + 4), "Netflix", font=resultFont, fill=(0, 0, 0))

		if not self.__hide_bilibili:
			draw.text((netflix_right_position + self.__getBasePos(bilibili_right_position - netflix_right_position, "Bilibili"), 30 + 4), "Bilibili", font=resultFont, fill=(0, 0, 0))

		if not self.__hide_stream:
			draw.text((bilibili_right_position + self.__getBasePos(stream_right_position - bilibili_right_position, "Streaming"), 30 + 4), "Streaming", font=resultFont, fill=(0, 0, 0))

		draw.line((0, 60, imageRightPosition - 1, 60), fill=(127, 127, 127), width=1)

		# Data rows
		onlineNode = 0
		for i in range(0, len(result)):
			if result[i].get("ping", 0) > 0:
				onlineNode += 1

			j = i + 1
			draw.line((0, 30 * j + 60, imageRightPosition, 30 * j + 60), fill=(127, 127, 127), width=1)
			item = result[i]

			# Group
			group = item.get("group", "N/A")
			draw.text((5, 30 * j + 30 + 4), group, font=resultFont, fill=(0, 0, 0))

			# Remarks
			remarks = item.get("remarks", "N/A")
			draw.text((groupRightPosition + 5, 30 * j + 30 + 4), remarks, font=resultFont, fill=(0, 0, 0))

			# Ping
			if not self.__hide_ping:
				ping = item.get("ping", 0)
				ping_str = "%d" % ping if ping > 0 else "Timeout"
				pos = remarkRightPosition + self.__getBasePos(pingRightPosition - remarkRightPosition, ping_str)
				draw.text((pos, 30 * j + 30 + 4), ping_str, font=resultFont, fill=(0, 0, 0))

			# Port
			if not self.__hide_port:
				port = "%d" % item.get("port", 0)
				pos = pingRightPosition + self.__getBasePos(portRightPosition - pingRightPosition, port)
				draw.text((pos, 30 * j + 30 + 4), port, font=resultFont, fill=(0, 0, 0))

			# NAT Type
			if not self.__hide_ntt:
				nat_type = item.get("ntt", {}).get("type", "")
				nat_display = nat_type if nat_type else "Unknown"
				pos = portRightPosition + self.__getBasePos(ntt_right_position - portRightPosition, nat_display)
				draw.text((pos, 30 * j + 30 + 1), nat_display, font=resultFont, fill=(0, 0, 0))

			# Netflix
			if not self.__hide_netflix:
				netflix_type = item.get("Ntype", "None")
				pos = ntt_right_position + self.__getBasePos(netflix_right_position - ntt_right_position, netflix_type)
				draw.text((pos, 30 * j + 30 + 1), netflix_type, font=resultFont, fill=(0, 0, 0))

			# Bilibili
			if not self.__hide_bilibili:
				bilibili_type = item.get("Bltype", "N/A")
				pos = netflix_right_position + self.__getBasePos(bilibili_right_position - netflix_right_position, bilibili_type)
				draw.text((pos, 30 * j + 30 + 1), bilibili_type, font=resultFont, fill=(0, 0, 0))

			# Streaming icons
			if not self.__hide_stream:
				netflix_type = item.get("Ntype", "None")
				hbo_type = item.get("Htype", False)
				disney_type = item.get("Dtype", False)
				youtube_type = item.get("Ytype", False)
				abema_type = item.get("Atype", False)
				bahamut_type = item.get("Btype", False)
				chatgpt_type = item.get("Ctype", False)
				bilibili_type = item.get("Bltype", "N/A")
				tvb_type = item.get("Ttype", False)
				
				n_type = netflix_type[:4] == "Full" if netflix_type else False
				bl_type = bilibili_type == "全解锁"
				
				sums = n_type + hbo_type + disney_type + youtube_type + abema_type + bahamut_type + tvb_type + bl_type + chatgpt_type
				pos = bilibili_right_position + (stream_right_position - bilibili_right_position - sums * 35) / 2 + 3
				
				if n_type:
					resultImg.paste(netflix_logo, (int(pos), 30 * j + 30 + 1))
					pos += 35
				if hbo_type:
					resultImg.paste(hbo_logo, (int(pos), 30 * j + 30 + 1))
					pos += 35
				if disney_type:
					resultImg.paste(disney_logo, (int(pos), 30 * j + 30 + 1))
					pos += 35
				if youtube_type:
					resultImg.paste(youtube_logo, (int(pos), 30 * j + 30 + 1))
					pos += 35
				if abema_type:
					resultImg.paste(abema_logo, (int(pos), 30 * j + 30 + 1))
					pos += 35
				if bahamut_type:
					resultImg.paste(bahamut_logo, (int(pos), 30 * j + 30 + 1))
					pos += 35
				if tvb_type:
					resultImg.paste(tvb_logo, (int(pos), 30 * j + 30 + 1))
					pos += 35
				if bl_type:
					resultImg.paste(bilibili_logo, (int(pos), 30 * j + 30 + 1))
					pos += 35
				if chatgpt_type:
					resultImg.paste(chatgpt_logo, (int(pos), 30 * j + 30 + 1))
					pos += 35

		# Footer
		draw.text((5, imageHeight + 30 + 4),
			"Time used: {}. Online Node(s): [{}/{}]".format(self.__timeUsed, onlineNode, len(result)),
			font=resultFont,
			fill=(0, 0, 0)
		)

		draw.text((5, imageHeight + 30 * 2 + 4),
			"Generated at {}".format(time.strftime("%Y-%m-%d %H:%M:%S", generatedTime)),
			font=resultFont,
			fill=(0, 0, 0)
		)
		draw.line((0, newImageHeight - 30 - 1, imageRightPosition, newImageHeight - 30 - 1), fill=(127, 127, 127), width=1)
		draw.line((0, newImageHeight - 1, imageRightPosition, newImageHeight - 1), fill=(127, 127, 127), width=1)

		filename = "./results/" + time.strftime("%Y-%m-%d-%H-%M-%S", generatedTime) + ".png"
		resultImg.save(filename)
		logger.info("Result image saved as %s" % filename)

	def __exportAsJson(self, result):
		filename = "./results/" + time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime()) + ".json"
		with open(filename, "w+", encoding="utf-8") as f:
			f.writelines(json.dumps(result, sort_keys=True, indent=4, separators=(',', ':')))
		logger.info("Result exported as %s" % filename)
		return result
