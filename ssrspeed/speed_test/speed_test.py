# coding:utf-8
import logging
import copy
import socket
import socks
import pynat
import requests
import json
import concurrent.futures
from ..clash_api import MihomoClient, node_to_clash_proxy, generate_clash_config
from config import config

logger = logging.getLogger("Sub")
LOCAL_ADDRESS = config["localAddress"]
LOCAL_PORT = config["localPort"]
NAT_TEST = config["ntt"]
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
MIHOMO_GROUP_NAME = "GLOBAL"


class SpeedTest(object):
    def __init__(self, parser):
        self.__configs = parser.nodes
        self.__results = []
        self.__current = {}
        self.__baseResult = {
            "group": "N/A",
            "remarks": "N/A",
            "loss": 1,
            "ping": 0,
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
        # init thread pool
        self.executor = concurrent.futures.ThreadPoolExecutor()
        # init Mihomo client
        self.__mihomo = None

    def __del__(self):
        # close the thread pool
        self.executor.shutdown()
        # stop Mihomo
        if self.__mihomo:
            self.__mihomo.stop()

    def __getBaseResult(self):
        return copy.deepcopy(self.__baseResult)

    def __getNextConfig(self):
        try:
            return self.__configs.pop(0)
        except IndexError:
            return None

    def resetStatus(self):
        self.__results = []
        self.__current = {}

    def getResult(self):
        return self.__results

    def getCurrent(self):
        return self.__current

    def getResponse(self, url):
        response = None
        try:
            if isinstance(url, str):
                response = requests.get(url, proxies=PROXIES, headers=HEADERS, timeout=8)
            else:
                response = requests.get(url[0], proxies=PROXIES, headers=HEADERS, timeout=8, cookies=url[1])
        except Exception as e:
            logger.error('Proxy connection error: ' + str(e.args))
        return response

    def __resetStreamVars(self):
        """Reset streaming detection variables for each node"""
        self.ntype = "None"
        self.htype = False
        self.dtype = False
        self.ytype = False
        self.ttype = False
        self.atype = False
        self.btype = False
        self.ctype = False
        self.bltype = "N/A"

    def __getStream(self):
        urls = []
        bahamut_code = 0

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
        results = list(self.executor.map(self.getResponse, urls))

        if NETFLIX_TEST:
            logger.info("Performing netflix test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                _sum = 0
                r1 = results.pop(0)
                r2 = results.pop(0)
                if r1 is not None and r2 is not None:
                    if r1.status_code == 200:
                        _sum += 1
                    rg = ""
                    if r2.status_code == 200:
                        _sum += 1
                        rg = r2.url.split("com/")[1].split("/")[0]
                        if rg != "title":
                            rg = str.upper(rg[:2])
                            rg = "(" + rg + ")"
                        else:
                            rg = ""
                    if _sum == 0:
                        logger.info("Netflix test result: None.")
                        self.ntype = "None"
                    elif _sum == 1:
                        logger.info("Netflix test result: Only Original.")
                        self.ntype = "Only Original"
                    else:
                        logger.info("Netflix test result: Full.")
                        self.ntype = "Full" + rg
                else:
                    self.ntype = "Unknown"
            except Exception as e:
                logger.error('Proxy connection error: ' + str(e.args))
        if HBO_TEST:
            logger.info("Performing HBO max test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r = results.pop(0)
                if r is not None and r.status_code == 200:
                    self.htype = True
            except Exception as e:
                logger.error('Proxy connection error: ' + str(e.args))
        if DISNEY_TEST:
            logger.info("Performing Disney plus test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r1 = results.pop(0)
                r2 = results.pop(0)
                if r1 is not None and r2 is not None:
                    if r1.status_code == 200 and r2.status_code != 403:
                        self.dtype = True
            except Exception as e:
                logger.error('Proxy connection error: ' + str(e.args))
        if YOUTUBE_TEST:
            logger.info("Performing Youtube Premium test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r = results.pop(0)
                if r is not None and r.status_code == 200:
                    self.ytype = True
            except Exception as e:
                logger.error('Proxy connection error: ' + str(e.args))
        if TVB_TEST:
            logger.info("Performing TVB test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r = results.pop(0)
                if r is not None:
                    tvb_region = json.loads(r.text)['region']
                    if tvb_region == 1:
                        self.ttype = True
            except Exception as e:
                logger.error('Proxy connection error: ' + str(e.args))
        if ABEMA_TEST:
            logger.info("Performing Abema test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r = results.pop(0)
                if r is not None and r.text.count("Country") > 0:
                    self.atype = True
            except Exception as e:
                logger.error('Proxy connection error: ' + str(e.args))
        if BAHAMUT_TEST and bahamut_code:
            logger.info("Performing Bahamut test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r = results.pop(0)
                if r is not None and r.text.count("animeSn") > 0:
                    self.btype = True
            except Exception as e:
                logger.error('Proxy connection error: ' + str(e.args))
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
                if r1 is not None and r2 is not None:
                    r2text = r2.text
                    r2index = r2text.find('loc=')
                    country_code = r2text[r2index + 4: r2index + 6]
                    if r1.text.count('Error reference number: 1020') == 0 and country_code in chatgpt_region_list:
                        self.ctype = True
            except Exception as e:
                logger.error('Proxy connection error: ' + str(e.args))
        if BILIBILI_TEST:
            logger.info("Performing Bilibili test LOCAL_PORT: {:d}.".format(LOCAL_PORT))
            try:
                r1 = results.pop(0)
                r2 = results.pop(0)
                _sum = 0
                if r1 is not None and r2 is not None:
                    if r1.text.count('抱歉您所在地区不可观看') == 0:
                        self.bltype = "仅限港澳台"
                        _sum += 1
                    if r2.text.count('抱歉您所在地区不可观看') == 0:
                        self.bltype = "仅限台湾"
                        _sum += 1
                    if _sum == 2:
                        self.bltype = "全解锁"
            except Exception as e:
                logger.error('Proxy connection error: ' + str(e.args))

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

    def __fillItem(self, item, nat=None):
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

    def __prepare_node_entry(self, node):
        item = self.__getBaseResult()
        cfg = node.config
        cfg["server_port"] = int(cfg["server_port"])
        item["group"] = cfg["group"]
        item["remarks"] = cfg["remarks"]
        item["port"] = cfg["server_port"]
        clash_proxy = node_to_clash_proxy(node)
        return {
            "node": node,
            "cfg": cfg,
            "item": item,
            "proxy": clash_proxy,
        }

    def __start_test(self):
        self.__results = []
        prepared_nodes = []

        node = self.__getNextConfig()
        while node:
            try:
                prepared_nodes.append(self.__prepare_node_entry(node))
            except Exception as e:
                logger.error(f"Failed to prepare node for testing: {e}")
                item = self.__getBaseResult()
                try:
                    cfg = node.config
                    item["group"] = cfg.get("group", "N/A")
                    item["remarks"] = cfg.get("remarks", "N/A")
                    item["port"] = int(cfg.get("server_port", 0))
                except Exception:
                    pass
                self.__results.append(item)
            node = self.__getNextConfig()

        total_nodes = len(prepared_nodes)
        if total_nodes == 0:
            logger.warning("No valid nodes to test.")
            self.__current = {}
            return

        # Start Mihomo once with all proxies loaded so delay checks can run in batch.
        self.__mihomo = MihomoClient(socks_port=LOCAL_PORT)

        try:
            clash_config = generate_clash_config(
                [entry["proxy"] for entry in prepared_nodes],
                socks_port=LOCAL_PORT,
                group_name=MIHOMO_GROUP_NAME
            )
        except Exception as e:
            logger.error(f"Failed to generate Clash config: {e}")
            self.__results.extend(entry["item"] for entry in prepared_nodes)
            return

        if not self.__mihomo.start(clash_config):
            logger.error("Failed to start Mihomo")
            self.__results.extend(entry["item"] for entry in prepared_nodes)
            return

        delay_map = self.__mihomo.test_group_delay(MIHOMO_GROUP_NAME, timeout=10000)
        if not delay_map:
            logger.warning("Batch group delay unavailable, falling back to per-proxy delay checks.")

        for entry in prepared_nodes:
            proxy_name = entry["proxy"]["name"]
            delay = delay_map.get(proxy_name)
            if delay > 0:
                entry["item"]["ping"] = int(delay)
                entry["item"]["loss"] = 0
                logger.info(f"Proxy {proxy_name} delay: {int(delay)}ms")
            else:
                logger.warning(f"Proxy {proxy_name} unreachable")
                entry["item"]["ping"] = 0
                entry["item"]["loss"] = 1

        for done_nodes, entry in enumerate(prepared_nodes, start=1):
            item = entry["item"]
            clash_proxy = entry["proxy"]
            nat_info = ""
            nat = None
            self.__resetStreamVars()

            try:
                logger.info(
                    "Starting test {group} - {remarks} [{cur}/{tol}]".format(
                        group=item["group"],
                        remarks=item["remarks"],
                        cur=done_nodes,
                        tol=total_nodes
                    )
                )

                self.__current = item

                if item["loss"] == 0:
                    if not self.__mihomo.select_proxy(MIHOMO_GROUP_NAME, clash_proxy["name"]):
                        logger.error(f"Failed to select proxy {clash_proxy['name']}")
                        item["loss"] = 1
                        item["ping"] = 0

                # stream detection
                if STREAM_TEST and item["loss"] == 0:
                    self.__getStream()

                # nat type test
                if NAT_TEST["enabled"] and item["loss"] == 0:
                    nat = self.__natTypeTest()
                    if nat[0]:
                        nat_info += " - NAT Type: " + nat[0]
                    if nat[0] and nat[0] != pynat.BLOCKED:
                        nat_info += " - Internal End: {}:{}".format(nat[3], nat[4])
                        nat_info += " - Public End: {}:{}".format(nat[1], nat[2])

                # fill result
                self.__fillItem(item, nat)

                logger.info(
                    "[{}] - [{}] - Ping: [{}ms] - Loss: [{:.0f}%]{}".format(
                        item["group"],
                        item["remarks"],
                        item["ping"],
                        item["loss"] * 100,
                        nat_info
                    )
                )
            except Exception:
                logger.exception("\n")
            finally:
                self.__results.append(item)

        # Stop Mihomo after all tests
        if self.__mihomo:
            self.__mihomo.stop()
            self.__mihomo = None

        self.__current = {}

    def startTest(self):
        """Start the connectivity test"""
        logger.info("Test mode: Connectivity test (Mihomo delay + streaming + NAT)")
        self.__start_test()
