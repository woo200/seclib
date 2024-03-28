from dataclasses import dataclass
from tor.net.util import is_port_in_use
from tor.tor_socket import TorSocket
import os

@dataclass
class HiddenService:
    local_ip: str
    local_port: int
    port: int
    dir: str
    hostname: str = None

    def __str__(self) -> str:
        return f"""HiddenServiceDir {self.dir}
HiddenServicePort {self.port} {self.local_ip}:{self.local_port}"""

    def get_hostname(self) -> str:
        if super().__getattribute__("hostname"):
            return super().__getattribute__("hostname")
        
        hostname_file = os.path.join(self.dir, "hostname")
        if not os.path.exists(hostname_file):
            raise FileNotFoundError(f"{hostname_file} not found. (Is tor running?)")
        with open(hostname_file) as f:
            self.hostname = f.read().rstrip()
        return super().__getattribute__("hostname")

    def __getattribute__(self, __name: str):
        if __name == "hostname":
            return self.get_hostname()
        return super().__getattribute__(__name)

class Controller:
    def __init__(self, **kwargs):
        self.args = {
            "socks_port": 9050,
            "torrc": "torrc",
            "debug": False,
            "hidden_services": [],
            **kwargs
        }
        self.pid = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()
        if exc_type:
            raise exc_value

    def start(self):
        raise NotImplementedError()

    def stop(self):
        if self.pid:
            self.pid.terminate()
            self.pid.wait()
    
    def running(self):
        return is_port_in_use(self.args["socks_port"])

    def add_hidden_service(self, local_ip, local_port, port, dir):
        self.args["hidden_services"].append(HiddenService(local_ip, local_port, port, dir))

    def get_hidden_service(self, index: int) -> HiddenService:
        return self.args["hidden_services"][index]

    def wait_for_service(self, index: int):
        svc = self.get_hidden_service(index)
        while True:
            try:
                svc.get_hostname()
                return
            except FileNotFoundError:
                pass
        
    def get_torsock(self):
        return TorSocket(port=self.args["socks_port"])

    def _generate_torrc(self):
        with open(self.args["torrc"], "w") as f:
            hiddenServices = "\n".join(map(str, self.args["hidden_services"]))
            f.write(f"""SocksPort {self.args["socks_port"]}
{hiddenServices}""")