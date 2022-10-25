import requests
import LogGrap
import LogFilter
import time
from collections import namedtuple
from ip2region.xdbSearcher import XdbSearcher

from Config import config

CHECK_DURATION = int(config.check_duration)
XDB_PATH = config.xdb_path


def my_custom_print(msg: str, end: str = '\n'):
    if msg.endswith('\r'):
        msg = msg[:-1] + ' ' * 10 + '\r'

    if config.udp_enable:
        import udp_server.udp_server
        udp_server.udp_server.send(msg, end)

    print(msg, end=end)


class IP2Region:

    def __init__(self, db_path):
        self.db_path = db_path

    def _init_xdb_searcher(self):
        # 1. 预先加载整个 xdb
        self._cb = XdbSearcher.loadContentFromFile(dbfile=self.db_path)

    def __enter__(self) -> XdbSearcher:
        self._init_xdb_searcher()
        # 2. 仅需要使用上面的全文件缓存创建查询对象, 不需要传源 xdb 文件
        self.searcher = XdbSearcher(contentBuff=self._cb)
        return self.searcher

    def __exit__(self, exc_type, exc_val, exc_tb):
        # 4. 关闭searcher
        self.searcher.close()


def check_threats(threat_list: dict):
    first_print_n = False       # 第一次打印时多打印一个\n，防止检测类型被覆盖
    with IP2Region(XDB_PATH) as searcher:

        for threat in threat_list:
            alert = LogFilter.LogFilterAlert()
            alert += LogFilter.filter_ip_region(threat, searcher)
            alert += LogFilter.filter_alert_msg(threat, ignore_lan=True)

            if alert.alert():
                if not first_print_n:
                    my_custom_print('')
                    first_print_n = True
                # 输出信息摘要
                my_custom_print(LogFilter.get_brief_info(threat))
                # 如果过滤后列表没有项，就不输出alert
                my_custom_print(repr(alert.alert())) if alert.alert() is not True else "pass"
                if config.bell_when_alert:
                    # 响铃
                    print('\a', end='')


# 上一次检查的最新条目的时间
threat_time_span = namedtuple('threat_time_span', 'latest oldest')
last_threats_time_span = {}


def main():
    global last_threats_time_span

    def fetch_threat_till_last(uri: str):

        def _update_oldest_time():
            # 更新oldest时间到现在表示已经更新过了
            if last_threats_time_span.get(uri) is not None:
                last_threats_time_span[uri] = threat_time_span(last_threats_time_span[uri].latest, int(time.time()))

        global last_threats_time_span

        # 获取最新威胁情报列表
        fetch_threat_list = LogGrap.fetch_threat_list_factory(uri)

        # 获取两组时间
        last_time_span = last_threats_time_span.get(uri, threat_time_span(None, None))  # 为了满足下一条命令定义的特殊值
        threat_list = fetch_threat_list(ss, int(time.time()), last_time_span.latest)

        # 如果列表是空列表
        if len(threat_list) == 0:
            _update_oldest_time()
            return

        # 通过时间追查，判断此次更新是否没有遗漏
        # 如果第一次运行，设置last_time_span使程序只检测一次即可。
        this_time_span = threat_time_span(LogFilter.get_time(threat_list[0]), LogFilter.get_time(threat_list[-1]))
        last_time_span = last_threats_time_span.get(uri, threat_time_span(this_time_span.oldest, 0))

        if this_time_span.latest <= last_time_span.latest:
            # 此次最新和上次最新相同，说明没有更新
            _update_oldest_time()
            return

        check_threats(threat_list)

        _i = 0   # 加载条目的次数
        while this_time_span.oldest > last_time_span.latest:
            # 如果这次更新最老的也比上次更新最新的要老
            # 那么更新有遗漏，循环拉取直到所有条目都被检测
            if _i == 0:
                print('')
            _i += 1
            my_custom_print(f"正在获取未加载的下一部分条目（第 {_i} 次）……\r", end='')
            threat_list = fetch_threat_list(ss, this_time_span.oldest, last_time_span.latest)
            check_threats(threat_list)

            # 扩展 this_time_span 到此次获取到所有条目的最新时间--最旧时间
            this_time_span = threat_time_span(this_time_span.latest, LogFilter.get_time(threat_list[-1]))

        # 这次更新结束后，这次最新条目的时间成为下一次更新条目的“上一次最新时间”
        last_threats_time_span[uri] = this_time_span

    ss = requests.session()
    ss.cookies['csrftoken'] = config.csrftoken.strip()
    ss.headers['Authorization'] = config.authorization.strip()

    while True:

        # 刷新token
        config.authorization = LogGrap.refresh_token(ss)
        config.csrftoken = ss.cookies.get('csrftoken', domain=config.domain)
        # 保存ss
        config.save_session()

        for i in range(len(LogGrap.URIS)):
            uri, desc = LogGrap.URIS[i]
            my_custom_print(f"\r查询 {desc} 条目...    ({i + 1}/{len(LogGrap.URIS)})      ", end='')
            time.sleep(0.1)
            fetch_threat_till_last(uri)

        my_custom_print(
            f"\r条目最新时间：{LogFilter.get_time_str(max(map(lambda span: span.latest, last_threats_time_span.values())))}      "
            f"\n条目最旧时间：{LogFilter.get_time_str(min(map(lambda span: span.oldest, last_threats_time_span.values())))}"
        )

        try:
            for i in range(CHECK_DURATION):
                # time.sleep(1)
                time.sleep(1)
                if i >= CHECK_DURATION - 1:
                    my_custom_print("\r", end='')
                else:
                    my_custom_print(f"\r距离下次刷新还有 {CHECK_DURATION - i - 1} s...", end='')
        except KeyboardInterrupt:
            my_custom_print("我溜啦！")
            break


if __name__ == '__main__':
    main()
