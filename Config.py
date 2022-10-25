import configparser
import os


class MyConfig(configparser.ConfigParser):
    CONFIG_SAVE_FILENAME = "config.ini"
    CONFIG_OPTIONS = (
        "check_duration",
        "xdb_path",
        "domain",
        "bell_when_alert",
    )
    SESSION_OPTIONS = (
        'csrftoken',
        'authorization'
    )
    UDP_SERVER_OPTIONS = (
        'enable',
        'port',
        'broadcast_addr',
        'simple_password',
    )
    SESSION_SECTIONS = (
        "ip_suffix_whitelist",
        "alert_type_whitelist"
    )

    def _get_options(self):
        """将获取的配置转存到config的属性中方便读取"""

        def _process_config_config():
            self.bell_when_alert = bool(int(self.bell_when_alert))

        def _process_udp_config():
            self.udp_port = int(self.udp_port)
            self.udp_enable = bool(int(self.udp_enable))

        for opt in MyConfig.CONFIG_OPTIONS:
            setattr(self, opt, self.get('config', opt))
        _process_config_config()

        for opt in MyConfig.SESSION_OPTIONS:
            setattr(self, opt, self.get('session', opt))

        for opt in MyConfig.UDP_SERVER_OPTIONS:
            setattr(self, f"udp_{opt}", self.get('udp server', opt))
        _process_udp_config()

        for sec in MyConfig.SESSION_SECTIONS:
            setattr(self, sec, self.options(sec))

    def optionxform(self, optionstr: str) -> str:
        # override 防止不区分大小写
        return optionstr

    def __init__(self):
        super(MyConfig, self).__init__()

        # 检测config.ini是否存在
        if not os.path.exists(MyConfig.CONFIG_SAVE_FILENAME):
            MyConfig.init_save()
            raise IOError("没有config.ini文件，请进行配置！")

        self.read(MyConfig.CONFIG_SAVE_FILENAME, encoding='utf-16')
        self._get_options()

    def save_session(self):
        # 保存ss信息，然后重读文件更新配置（防止程序运行中的配置更新），之后把新配置保存
        # TODO: 配置热更新
        tmp = tuple(getattr(self, val) for val in MyConfig.SESSION_OPTIONS)
        self.read(MyConfig.CONFIG_SAVE_FILENAME, encoding='utf-16')
        for i in range(len(MyConfig.SESSION_OPTIONS)):
            self.set('session', MyConfig.SESSION_OPTIONS[i], tmp[i])

        with open(MyConfig.CONFIG_SAVE_FILENAME, 'w', encoding='utf-16') as cpf:
            self.write(cpf, True)

        # 更新self的attr
        self._get_options()

    @staticmethod
    def init_save():
        cp = configparser.ConfigParser()
        cp.add_section('config')
        cp.set("config", MyConfig.CONFIG_OPTIONS[0], "120")
        cp.set("config", MyConfig.CONFIG_OPTIONS[1], "./ip2region/ip2region.xdb")
        cp.set("config", MyConfig.CONFIG_OPTIONS[2], "127.0.0.1")
        cp.set("config", MyConfig.CONFIG_OPTIONS[3], "1")

        cp.add_section('session')
        cp.set("session", MyConfig.SESSION_OPTIONS[0], 'None')
        cp.set("session", MyConfig.SESSION_OPTIONS[1], 'None')

        cp.add_section('udp server')
        cp.set("udp server", MyConfig.UDP_SERVER_OPTIONS[0], '0')  # 1为开启，0为关闭
        cp.set("udp server", MyConfig.UDP_SERVER_OPTIONS[1], '10517')
        cp.set("udp server", MyConfig.UDP_SERVER_OPTIONS[2], '127.0.0.1')
        cp.set("udp server", MyConfig.UDP_SERVER_OPTIONS[3], '')  # 没有密码则不加密

        cp.add_section(MyConfig.SESSION_SECTIONS[0])
        cp.set(MyConfig.SESSION_SECTIONS[0], '0.', '')
        cp.set(MyConfig.SESSION_SECTIONS[0], '10.', '')
        cp.set(MyConfig.SESSION_SECTIONS[0], '172.16.', '')
        cp.set(MyConfig.SESSION_SECTIONS[0], '192.168.', '')
        cp.add_section(MyConfig.SESSION_SECTIONS[1])
        cp.set(MyConfig.SESSION_SECTIONS[1], 'FTP服务用户弱口令认证', '')

        with open(MyConfig.CONFIG_SAVE_FILENAME, 'w', encoding='utf-16') as cpf:
            cp.write(cpf, True)


config = MyConfig()

if __name__ == '__main__':
    for v in (*MyConfig.CONFIG_OPTIONS, *MyConfig.SESSION_OPTIONS, *MyConfig.SESSION_SECTIONS):
        print(getattr(config, v, f'{v} Not Found!'))
