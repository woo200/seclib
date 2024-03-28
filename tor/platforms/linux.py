import subprocess
import shutil

from tor.controller import Controller

class LinuxController(Controller):
    def __is_installed(self):
        return shutil.which("tor") is not None

    def __install(self):
        if self.__is_installed():
            return
        print("Installing Tor... Please enter your password...")
        subprocess.run(["sudo", "apt-get", "install", "-y", "tor"])

    def start(self):
        if not self.__is_installed():
            self.__install()
        self._generate_torrc()

        if self.args["debug"]:
            self.pid = subprocess.Popen(["tor", "-f", self.args["torrc"]])
        else:
            self.pid = subprocess.Popen(["tor", "-f", self.args["torrc"]],
                                        stdout=subprocess.DEVNULL, 
                                        stderr=subprocess.DEVNULL)
