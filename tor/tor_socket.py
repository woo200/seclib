import sockslib

from tor.net.util import is_port_in_use

class TorSocket(sockslib.SocksSocket):
    def __init__(self, **kwargs):
        super().__init__()
        self.args = {
            "port": 9050,
        }
        self.set_proxy(('127.0.0.1', self.args["port"]))
    
    def connect(self, host):
        if not is_port_in_use(self.args["port"]):
            raise ConnectionError("Tor is not running")
        return super().connect(host)