import typing
import ip2region.xdbSearcher as xdbSearcher
from datetime import datetime

from Config import config

IP_SUFFIX_WHITELIST = config.ip_suffix_whitelist
ALERT_TYPE_WHITELIST = config.alert_type_whitelist


class LogFilterAlert:
    ### ALERT 警告规则：
    ###     函数返回任何信息（列表，文本等）则输出警告信息和该条简要详情
    ###     函数返回 True 则只输出该条摘要，但 True 被过滤不显示。

    def __init__(self, ):
        self.alert_list = []
        self._alert_result = None

    def __iadd__(self, other):
        self.alert_list.append(other)
        return self

    def alert(self) -> typing.Union[typing.Tuple, bool]:
        """根据目前所有结果输出警告。只能计算一次，第二次将输出相同的结果。"""
        if self._alert_result is not None:
            return self._alert_result

        # 过滤掉所有的None和空列表等 !=True 的项
        self.alert_list = tuple(filter(lambda single_alert: single_alert, self.alert_list))

        if self.alert_list:
            # 警告列表在被过滤后仍有余项，则过滤掉所有为True的项用于最后输出
            self.alert_list = tuple(filter(lambda single_alert: single_alert is not True, self.alert_list))
            # 如果最后列表为空，则证明源列表里只剩下True项，就直接返回True
            self._alert_result = self.alert_list if self.alert_list else True
        else:
            self._alert_result = False

        return self._alert_result


def get_ips(item: typing.Dict) -> typing.Tuple[str, str]:
    """返回源-目的IP"""
    return item.get('IPv4NumToString(sip4)', '0.'), item.get('IPv4NumToString(dip4)', '0.')


def check_ip_suffix_in_whitelist(ip: str) -> bool:
    return any([ip.startswith(suffix) for suffix in IP_SUFFIX_WHITELIST])


def filter_ip_region(threat_item: typing.Dict, xdb_searcher: xdbSearcher.XdbSearcher) -> typing.List:
    """检测IP归属地。若原地址或目的地址有一个是境外IP则报警。"""

    result = []

    ip_src, ip_dst = get_ips(threat_item)

    # 检测IP前缀白名单
    if not check_ip_suffix_in_whitelist(ip_src):
        addr_str = xdb_searcher.search(ip_src)
        if '中国' not in addr_str:
            result.append(f"警告，源IP {ip_src} 似乎不是中国IP！位置：{addr_str}")

    if not check_ip_suffix_in_whitelist(ip_dst):
        addr_str = xdb_searcher.search(ip_dst)
        if '中国' not in addr_str:
            result.append(f"警告，目的IP {ip_dst} 似乎不是中国IP！位置：{addr_str}")

    return result


def filter_alert_msg(threat_item: typing.Dict, ignore_lan=False) -> typing.Union[None, bool]:
    """检测警告信息是否在白名单中。若发起者是内网IP，则开启白名单过滤，在白名单内的行为不报警。"""
    if any([threat_item['msg'] == white_msg.lower() for white_msg in ALERT_TYPE_WHITELIST]):
        # msg在白名单中
        # print(threat_item['msg'])

        # 查看是否是白名单中的IP
        ips = get_ips(threat_item)
        if ignore_lan and check_ip_suffix_in_whitelist(ips[0]):
            # 如果设置了忽略内网，且源地址是内网，则忽略
            return None
        else:
            # 如果不是白名单中的IP，则msg规则过滤无效，直接返回True
            return True
    else:
        # msg不在白名单中
        return True


def get_time_str(item: typing.Union[typing.Dict, int]) -> datetime:
    """返回格式化后的条目时间"""
    timestamp = item if isinstance(item, int) else item['toUnixTimestamp(timestamp)']
    return datetime.fromtimestamp(timestamp)


def get_time(item: typing.Dict) -> int:
    return item['toUnixTimestamp(timestamp)']


def get_brief_info(item: typing.Dict) -> str:
    ips = get_ips(item)
    return f"[{get_time_str(item)}] {ips[0]}:{item['sport']} --> {ips[1]}:{item['dport']}\t{item['msg']}"
