# coding:utf-8
import logging
import copy
import socket
import socks
import time
import json
import pynat
import requests
import concurrent.futures
from bs4 import BeautifulSoup
from .test_methods import SpeedTestMethods
from ..client_launcher import ShadowsocksClient, ShadowsocksRClient, V2RayClient, TrojanClient
from ..utils.geo_ip import domain2ip, parseLocation, IPLoc
from ..utils.port_checker import check_port
from config import config

logger = logging.getLogger("Sub")
LOCAL_ADDRESS = config["localAddress"]
LOCAL_PORT = config["localPort"]
PING_TEST = config["ping"]
GOOGLE_PING_TEST = config["gping"]
NAT_TEST = config["ntt"]
GEO_TEST = config["geoip"]
STREAM_TEST = config["stream"]
NETFLIX_TEST = config["netflix"]
HBO_TEST = config["hbo"]
DISNEY_TEST = config["disney"]
YOUTUBE_TEST = config["youtube"]
ABEMA_TEST = config["abema"]
BAHAMUT_TEST = config["bahamut"]
BILIBILI_TEST = config["bilibili"]
TVB_TEST = config["tvb"]
CHATGPT_TEST = config["chatgpt"]
PROXIES = {
    "http": "socks5h://127.0.0.1:%d" % LOCAL_PORT,
    "https": "socks5h://127.0.0.1:%d" % LOCAL_PORT
}
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36"
}


class SpeedTest(object):
    def __init__(self, parser, method="SOCKET", use_ssr_cs=False):
        self.__configs = parser.nodes
        self.__use_ssr_cs = use_ssr_cs
        self.__testMethod = method
        self.__results = []
        self.__current = {}
        self.__baseResult = {
            "group": "N/A",
            "remarks": "N/A",
            "loss": 1,
            "ping": 0,
            "gPingLoss": 1,
            "gPing": 0,
            "dspeed": -1,
            "maxDSpeed": -1,
            "trafficUsed": 0,
            "geoIP": {
                "inbound": {
                    "address": "N/A",
                    "info": "N/A"
                },
                "outbound": {
                    "address": "N/A",
                    "info": "N/A"
                }
            },
            "rawSocketSpeed": [],
            "rawTcpPingStatus": [],
            "rawGooglePingStatus": [],
            "webPageSimulation": {
                "results": []
            },
            "ntt": {
                "type": "",
                "internal_ip": "",
                "internal_port": 0,
                "public_ip": "",
                "public_port": 0
            },
            "Ntype": "None",
            "Htype": False,
            "Dtype": False,
            "Ytype": False,
            "Ttype": False,
            "Atype": False,
            "Btype": False,
            "Ctype": False,
            "Bltype": "N/A",
            "InRes": "N/A",
            "OutRes": "N/A",
            "InIP": "N/A",
            "OutIP": "N/A",
            "port": 0,
        }
        # init all variables
        self.ntype = self.__baseResult["Ntype"]
        self.htype = self.__baseResult["Htype"]
        self.dtype = self.__baseResult["Dtype"]
        self.ytype = self.__baseResult["Ytype"]
        self.ttype = self.__baseResult["Ttype"]
        self.atype = self.__baseResult["Atype"]
        self.btype = self.__baseResult["Btype"]
        self.ctype = self.__baseResult["Ctype"]
        self.bltype = self.__baseResult["Bltype"]
        self.inboundGeoRES = self.__baseResult["InRes"]
        self.outboundGeoRES = self.__baseResult["OutRes"]
        self.inboundGeoIP = self.__baseResult["InIP"]
        self.outboundGeoIP = self.__baseResult["OutIP"]
        # init thread pool
        self.executor = concurrent.futures.ThreadPoolExecutor()

    def __del__(self):
        # close the thread pool
        self.executor.shutdown()

    def __getBaseResult(self):
        return copy.deepcopy(self.__baseResult)

    def __getNextConfig(self):
        try:
            return self.__configs.pop(0)
        except IndexError:
            return None

    def __getClient(self, client_type: str):
        if client_type == "Shadowsocks":
            return ShadowsocksClient()
        elif client_type == "ShadowsocksR":
            client = ShadowsocksRClient()
            if self.__use_ssr_cs:
                client.useSsrCSharp = True
            return client
        elif client_type == "V2Ray":
            return V2RayClient()
        elif client_type == "Trojan":
            return TrojanClient()
        else:
            return None

    def __checkClientPort(self, client):
        # Check client started
        client_started = False
        for attempt in range(3):
            time.sleep(1)
            if client.check_alive():
                client_started = True
                break
        # Check port
        port_opened = False
        for attempt in range(3):
            time.sleep(1)
            try:
                check_port(LOCAL_PORT)
                port_opened = True
                break
            except:
                pass
        if client_started and port_opened:
            logger.info("Client started.")
            return True
        else:
            logger.error("Failed to start client.")
            return False

    def resetStatus(self):
        self.__results = []
        self.__current = {}

    def getResult(self):
        return self.__results

    def getCurrent(self):
        return self.__current

    def getResponse(self, url):
        response = 0
        try:
            if isinstance(url, str):
                response = requests.get(url, proxies=PROXIES, headers=HEADERS, timeout=8)
            else:
                response = requests.get(url[0], proxies=PROXIES, headers=HEADERS, timeout=8, cookies=url[1])
        except Exception as e:
            logger.error('代理服务器连接异常：' + str(e.args))
        return response

    def __geoIPInbound(self, _cfg):
        inbound_ip = domain2ip(_cfg["server"])
        inbound_info = IPLoc(inbound_ip)
        inbound_geo = "{} {}, {}".format(
            inbound_info.get("country", "N/A"),
            inbound_info.get("city", "Unknown City"),
            inbound_info.get("organization", "N/A")
        )
        self.inboundGeoIP = inbound_ip
        self.inboundGeoRES = "{}, {}".format(
            inbound_info.get("city", "Unknown City"),
            inbound_info.get("organization", "N/A")
        )
        logger.info(
            "Node inbound IP : {}, Geo : {}".format(
                inbound_ip,
                inbound_geo
            )
        )
        return inbound_ip, inbound_geo, inbound_info.get("country_code", "N/A")

    def __geoIPOutbound(self):
        outbound_info = IPLoc()
        outbound_ip = outbound_info.get("ip", "N/A")
        outbound_geo = "{} {}, {}".format(
            outbound_info.get("country", "N/A"),
            outbound_info.get("city", "Unknown City"),
            outbound_info.get("organization", "N/A")
        )
        self.outboundGeoIP = outbound_ip
        self.outboundGeoRES = "{}, {}".format(
            outbound_info.get("country_code", "N/A"),
            outbound_info.get("organization", "N/A")
        )
        logger.info(
            "Node outbound IP : {}, Geo : {}".format(
                outbound_ip,
                outbound_geo
            )
        )
        return outbound_ip, outbound_geo, outbound_info.get("country_code", "N/A")

    def __getStream(self, outbound_ip=None):
        urls = []
        if NETFLIX_TEST:
            urls.append("https://www.netflix.com/title/70242311")
            urls.append("https://www.netflix.com/title/70143836")
        if HBO_TEST:
            urls.append("https://www.hbomax.com/")
        if DISNEY_TEST:
            urls.append("https://www.disneyplus.com/")
            urls.append("https://global.edge.bamgrid.com/token")
        if YOUTUBE_TEST:
            urls.append("https://music.youtube.com/")
        if TVB_TEST:
            urls.append("https://www.mytvsuper.com/api/auth/getSession/self/")
        if ABEMA_TEST:
            urls.append("https://api.abema.io/v1/ip/check?device=android")
        if BAHAMUT_TEST:
            bahamut_code = 1
            try:
                r = requests.get("https://ani.gamer.com.tw/ajax/getdeviceid.php", proxies=PROXIES, headers=HEADERS,
                                 timeout=8)
                device_id = json.loads(r.text)['deviceid']
                logger.info("BAHAMUT device id: {}".format(device_id))
                urls.append(("https://ani.gamer.com.tw/ajax/token.php?adID=89422&sn=14667&device={}".format(device_id),
                             r.cookies))
            except:
                bahamut_code = 0
        if CHATGPT_TEST:
            urls.append("https://chat.openai.com/backend-api/accounts/check")
            urls.append("https://chat.openai.com/cdn-cgi/trace")
        if BILIBILI_TEST:
            urls.append(
                "https://api.bilibili.com/pgc/player/web/playurl?avid=18281381&cid=29892777&qn=0&type=&otype=json&ep_id=183799&fourk=1&fnver=0&fnval=16")
            urls.append(
                "https://api.bilibili.com/pgc/player/web/playurl?avid=50762638&cid=100279344&qn=0&type=&otype=json&ep_id=268176&fourk=1&fnver=0&fnval=16")

        # perform all requests
        results = self.executor.map(self.getResponse, urls)
        results = list(results)

        if NETFLIX_TEST:
            logger.info("Performing netflix test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                _sum = 0
                r1 = results.pop(0)
                r2 = results.pop(0)
                netflix_ip = "netflix_ip"
                if r1 != 0 and r2 != 0:
                    if r1.status_code == 200:
                        _sum += 1
                        soup = BeautifulSoup(r1.text, "html.parser")
                        netflix_ip_str = str(soup.find_all("script"))
                        p1 = netflix_ip_str.find("requestIpAddress")
                        netflix_ip_r = netflix_ip_str[p1 + 19:p1 + 60]
                        p2 = netflix_ip_r.find(",")
                        netflix_ip = netflix_ip_r[0:p2]
                        logger.info("Netflix IP : " + netflix_ip)
                    rg = ""
                    if r2.status_code == 200:
                        _sum += 1
                        rg = r2.url.split("com/")[1].split("/")[0]
                        if rg != "title":
                            rg = str.upper(rg[:2])
                            rg = "(" + rg + ")"
                        else:
                            rg = ""
                    # 测试连接状态
                    if _sum == 0:
                        logger.info("Netflix test result: None.")
                        self.ntype = "None"
                    elif _sum == 1:
                        logger.info("Netflix test result: Only Original.")
                        self.ntype = "Only Original"
                    elif outbound_ip and outbound_ip[0] == netflix_ip:
                        logger.info("Netflix test result: Full Native.")
                        self.ntype = "Full Native" + rg
                    else:
                        logger.info("Netflix test result: Full DNS.")
                        self.ntype = "Full DNS" + rg
                else:
                    self.ntype = "Unknown"
            except Exception as e:
                logger.error('代理服务器连接异常：' + str(e.args))
        if HBO_TEST:
            logger.info("Performing HBO max test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r = results.pop(0)
                if r != 0 and r.status_code == 200:
                    self.htype = True
            except Exception as e:
                logger.error('代理服务器连接异常：' + str(e.args))
        if DISNEY_TEST:
            logger.info("Performing Disney plus test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r1 = results.pop(0)
                r2 = results.pop(0)
                if r1 != 0 and r2 != 0:
                    if r1.status_code == 200 and r2.status_code != 403:
                        self.dtype = True
            except Exception as e:
                logger.error('代理服务器连接异常：' + str(e.args))
        if YOUTUBE_TEST:
            logger.info("Performing Youtube Premium test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r = results.pop(0)
                if r != 0 and r.status_code == 200:
                    self.ytype = True
            except Exception as e:
                logger.error('代理服务器连接异常：' + str(e.args))
        if TVB_TEST:
            logger.info("Performing TVB test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r = results.pop(0)
                if r != 0:
                    tvb_region = json.loads(r.text)['region']
                    if tvb_region == 1:
                        self.ttype = True
            except Exception as e:
                logger.error('代理服务器连接异常：' + str(e.args))
        if ABEMA_TEST:
            logger.info("Performing Abema test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r = results.pop(0)
                if r != 0 and r.text.count("Country") > 0:
                    self.atype = True
            except Exception as e:
                logger.error('代理服务器连接异常：' + str(e.args))
        if BAHAMUT_TEST and bahamut_code:
            logger.info("Performing Bahamut test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r = results.pop(0)
                if r != 0 and r.text.count("animeSn") > 0:
                    self.btype = True
            except Exception as e:
                logger.error('代理服务器连接异常：' + str(e.args))
        if CHATGPT_TEST:
            logger.info("Performing ChatGPT test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            chatgpt_region_list = ['T1', 'XX', 'AL', 'DZ', 'AD', 'AO', 'AG', 'AR', 'AM', 'AU', 'AT', 'AZ', 'BS', 'BD',
                                   'BB', 'BE', 'BZ', 'BJ', 'BT', 'BA', 'BW', 'BR',
                                   'BG', 'BF', 'CV', 'CA', 'CL', 'CO', 'KM', 'CR', 'HR', 'CY', 'DK', 'DJ', 'DM', 'DO',
                                   'EC', 'SV', 'EE', 'FJ', 'FI', 'FR', 'GA', 'GM',
                                   'GE', 'DE', 'GH', 'GR', 'GD', 'GT', 'GN', 'GW', 'GY', 'HT', 'HN', 'HU', 'IS', 'IN',
                                   'ID', 'IQ', 'IE', 'IL', 'IT', 'JM', 'JP', 'JO',
                                   'KZ', 'KE', 'KI', 'KW', 'KG', 'LV', 'LB', 'LS', 'LR', 'LI', 'LT', 'LU', 'MG', 'MW',
                                   'MY', 'MV', 'ML', 'MT', 'MH', 'MR', 'MU', 'MX',
                                   'MC', 'MN', 'ME', 'MA', 'MZ', 'MM', 'NA', 'NR', 'NP', 'NL', 'NZ', 'NI', 'NE', 'NG',
                                   'MK', 'NO', 'OM', 'PK', 'PW', 'PA', 'PG', 'PE',
                                   'PH', 'PL', 'PT', 'QA', 'RO', 'RW', 'KN', 'LC', 'VC', 'WS', 'SM', 'ST', 'SN', 'RS',
                                   'SC', 'SL', 'SG', 'SK', 'SI', 'SB', 'ZA', 'ES',
                                   'LK', 'SR', 'SE', 'CH', 'TH', 'TG', 'TO', 'TT', 'TN', 'TR', 'TV', 'UG', 'AE', 'US',
                                   'UY', 'VU', 'ZM', 'BO', 'BN', 'CG', 'CZ', 'VA',
                                   'FM', 'MD', 'PS', 'KR', 'TW', 'TZ', 'TL', 'GB']
            try:
                r1 = results.pop(0)
                r2 = results.pop(0)
                if r1 != 0 and r2 != 0:
                    r2text = r2.text
                    r2index = r2text.find('loc=')
                    country_code = r2text[r2index + 4: r2index + 6]
                    if r1.text.count('Error reference number: 1020') == 0 and country_code in chatgpt_region_list:
                        self.ctype = True
            except Exception as e:
                logger.error('代理服务器连接异常：' + str(e.args))
        if BILIBILI_TEST:
            logger.info("Performing Bilibili test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r1 = results.pop(0)
                r2 = results.pop(0)
                _sum = 0
                if r1 != 0 and r2 != 0:
                    if r1.text.count('抱歉您所在地区不可观看') == 0:
                        self.bltype = "仅限港澳台"
                        _sum += 1
                    if r2.text.count('抱歉您所在地区不可观看') == 0:
                        self.bltype = "仅限台湾"
                        _sum += 1
                    if _sum == 2:
                        self.bltype = "全解锁"
            except Exception as e:
                logger.error('代理服务器连接异常：' + str(e.args))

    def __tcpPing(self, server, port):
        res = {
            "loss": self.__baseResult["loss"],
            "ping": self.__baseResult["ping"],
            "rawTcpPingStatus": self.__baseResult["rawTcpPingStatus"],
            "gPing": self.__baseResult["gPing"],
            "gPingLoss": self.__baseResult["gPingLoss"],
            "rawGooglePingStatus": self.__baseResult["rawGooglePingStatus"]
        }
        if PING_TEST:
            st = SpeedTestMethods()
            ping_test = st.tcpPing(server, port)
            res["loss"] = 1 - ping_test[1]
            res["ping"] = ping_test[0]
            res["rawTcpPingStatus"] = ping_test[2]
            time.sleep(1)
        if GOOGLE_PING_TEST:
            try:
                st = SpeedTestMethods()
                google_ping_test = st.googlePing()
                res["gPing"] = google_ping_test[0]
                res["gPingLoss"] = 1 - google_ping_test[1]
                res["rawGooglePingStatus"] = google_ping_test[2]
            except:
                pass
        return res

    def __natTypeTest(self):
        s = socks.socksocket(socket.AF_INET, socket.SOCK_DGRAM)
        s.set_proxy(socks.PROXY_TYPE_SOCKS5, LOCAL_ADDRESS, LOCAL_PORT)
        sport = NAT_TEST["internal_port"]
        try:
            logger.info("Performing UDP NAT Type Test")
            t, eip, eport, sip = pynat.get_ip_info(
                source_ip=NAT_TEST["internal_ip"],
                source_port=sport,
                include_internal=True,
                sock=s
            )
            return t, eip, eport, sip, sport
        except:
            logger.exception("\n")
            return None, None, None, None, None
        finally:
            s.close()

    def __fillItem(self, item, nat=None, speed=None, web=None, inbound_info=None, outbound_info=None):
        # stream
        item["Ntype"] = self.ntype
        item["Htype"] = self.htype
        item["Dtype"] = self.dtype
        item["Ytype"] = self.ytype
        item["Ttype"] = self.ttype
        item["Atype"] = self.atype
        item["Btype"] = self.btype
        item["Ctype"] = self.ctype
        item["Bltype"] = self.bltype
        # nat
        if nat:
            item["ntt"]["type"] = nat[0]
            item["ntt"]["public_ip"] = nat[1]
            item["ntt"]["public_port"] = nat[2]
            item["ntt"]["internal_ip"] = nat[3]
            item["ntt"]["internal_port"] = nat[4]
        # speed
        if speed:
            try:
                item["dspeed"] = speed[0]
                item["maxDSpeed"] = speed[1]
                item["rawSocketSpeed"] = speed[2]
                item["trafficUsed"] = speed[3]
            except:
                pass
        # web speed
        if web:
            item["webPageSimulation"]["results"] = web
        # geo
        item["InRes"] = self.inboundGeoRES
        item["OutRes"] = self.outboundGeoRES
        item["InIP"] = self.inboundGeoIP
        item["OutIP"] = self.outboundGeoIP
        if inbound_info:
            item["geoIP"]["inbound"]["address"] = inbound_info[0]
            item["geoIP"]["inbound"]["info"] = inbound_info[1]
        if outbound_info:
            item["geoIP"]["outbound"]["address"] = outbound_info[0]
            item["geoIP"]["outbound"]["info"] = outbound_info[1]

    def __start_test(self, test_mode="FULL"):
        self.__results = []
        total_nodes = len(self.__configs)
        done_nodes = 0
        node = self.__getNextConfig()
        while node:
            done_nodes += 1
            client = None
            item = self.__getBaseResult()
            try:
                cfg = node.config
                cfg["server_port"] = int(cfg["server_port"])
                item["group"] = cfg["group"]
                item["remarks"] = cfg["remarks"]
                item["port"] = cfg["server_port"]
                logger.info(
                    "Starting test {group} - {remarks} [{cur}/{tol}]".format(
                        group=cfg["group"],
                        remarks=cfg["remarks"],
                        cur=done_nodes,
                        tol=total_nodes
                    )
                )
                client = self.__getClient(node.node_type)
                if not client:
                    logger.warning(f"Unknown Node Type: {node.node_type}")
                    continue
                self.__current = item
                client.startClient(cfg)
                if not self.__checkClientPort(client):
                    continue

                # geo
                inbound_info = None
                outbound_info = None
                if GEO_TEST:
                    inbound_info = self.__geoIPInbound(cfg)
                    outbound_info = self.__geoIPOutbound()
                # ping
                ping_result = self.__tcpPing(cfg["server"], cfg["server_port"])
                if isinstance(ping_result, dict):
                    for k in ping_result.keys():
                        item[k] = ping_result[k]
                # stream
                if STREAM_TEST:
                    self.__getStream(outbound_info)
                # nat
                nat_info = ""
                nat = None
                if NAT_TEST["enabled"]:
                    nat = self.__natTypeTest()
                    if nat[0]:
                        nat_info += " - NAT Type: " + nat[0]
                    if nat[0] and nat[0] != pynat.BLOCKED:
                        nat_info += " - Internal End: {}:{}".format(nat[3], nat[4])
                        nat_info += " - Public End: {}:{}".format(nat[1], nat[2])
                # speed
                st = SpeedTestMethods()
                web = None
                speed = None
                if test_mode == "WPS":
                    web = st.startWpsTest()
                if test_mode == "FULL":
                    speed = st.startTest(self.__testMethod)
                    if int(speed[0]) == 0:
                        logger.warning("Re-testing node.")
                        speed = st.startTest(self.__testMethod)

                # fill
                self.__fillItem(item, nat, speed, web, inbound_info, outbound_info)
                if (not GOOGLE_PING_TEST) or item["gPing"] > 0 or (outbound_info and outbound_info[2] == "CN"):
                    if test_mode == "WPS":
                        logger.info(
                            "[{}] - [{}] - Loss: [{:.2f}%] - TCP Ping: [{:.2f}] - Google Loss: [{:.2f}%] - Google Ping: [{:.2f}] - [WebPageSimulation]".format
                                (
                                item["group"],
                                item["remarks"],
                                item["loss"] * 100,
                                int(item["ping"] * 1000),
                                item["gPingLoss"] * 100,
                                int(item["gPing"] * 1000)
                            )
                        )
                    elif test_mode == "PING":
                        logger.info(
                            "[{}] - [{}] - Loss: [{:.2f}%] - TCP Ping: [{:.2f}] - Google Loss: [{:.2f}%] - Google Ping: [{:.2f}]{}".format
                                (
                                item["group"],
                                item["remarks"],
                                item["loss"] * 100,
                                int(item["ping"] * 1000),
                                item["gPingLoss"] * 100,
                                int(item["gPing"] * 1000),
                                nat_info
                            )
                        )
                    elif test_mode == "FULL":
                        logger.info(
                            "[{}] - [{}] - Loss: [{:.2f}%] - TCP Ping: [{:.2f}] - Google Loss: [{:.2f}%] - Google Ping: [{:.2f}] - AvgStSpeed: [{:.2f}MB/s] - AvgMtSpeed: [{:.2f}MB/s]{}".format
                                (
                                item["group"],
                                item["remarks"],
                                item["loss"] * 100,
                                int(item["ping"] * 1000),
                                item["gPingLoss"] * 100,
                                int(item["gPing"] * 1000),
                                item["dspeed"] / 1024 / 1024,
                                item["maxDSpeed"] / 1024 / 1024,
                                nat_info
                            )
                        )
                    else:
                        logger.error(f"Unknown Test Mode {test_mode}")
            except Exception:
                logger.exception("\n")
            finally:
                self.__results.append(item)
                if client:
                    client.stopClient()
                node = self.__getNextConfig()
                time.sleep(1)
        self.__current = {}

    def webPageSimulation(self):
        logger.info("Test mode : Web Page Simulation")
        self.__start_test("WPS")

    def tcpingOnly(self):
        logger.info("Test mode : tcp ping only.")
        self.__start_test("PING")

    def fullTest(self):
        logger.info("Test mode : speed and tcp ping.Test method : {}.".format(self.__testMethod))
        self.__start_test("FULL")
