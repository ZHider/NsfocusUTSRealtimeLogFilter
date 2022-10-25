import requests
import typing
import time

from Config import config

URIS = (
    ("threat_ips", "入侵检测"),
    ("threat_waf", "Web应用告警"),
    ("threat_fiveg", "5G告警"),
    ("threat_sdk", "恶意文件告警"),
    ("threat_nti", "威胁情报告警"),
    ("threat_webshell", "Webshell告警"),
    ("threat_customrule", "自定义规则告警"),
)


def refresh_token(ss: requests.Session) -> str:
    resp = ss.get('https://172.200.210.206/webapi/v1/refreshtoken', verify=False)

    try:
        resp_json = resp.json()
    except:
        raise ValueError(f"Token获取错误。详细信息：{resp.text}")

    if resp.status_code == 200:
        token: str = resp_json['data']['token']
        ss.headers['Authorization'] = token
        print("Token 更新成功：" + token)

        return token
    else:
        raise ValueError(resp.text)


def fetch_threat_list_factory(type: str) -> typing.Callable:

    def _inner(
            ss: requests.Session,
            start_time: int = None, end_time: int = None
    ) -> typing.Union[typing.Dict, str]:

        start_time = start_time or int(time.time())
        end_time = end_time or start_time - 3600
        resp = ss.get(
            'https://{}/webapi/v1/log/{}?' \
            'sip=&sport=&dip=&dport=&ruleid=&alertlevel=&judge_ret=&pag=1&pag_cnt={}&' \
            'direct=&attack_chain=&sid=&start_time={}&end_time={}' \
                .format(config.domain, type, 100, end_time, start_time),
            verify=False
        )

        # 获取失败则返回str内容
        if resp.status_code == 200:
            return resp.json()['data']
        else:
            return resp.text

    return _inner


