__version__ = "0.1.0"

import platform

from tor.platforms.linux import LinuxController
from tor.platforms.windows import WindowsController
from tor.controller import Controller, HiddenService

TorController: Controller

if platform.system() == "Linux":
    TorController = LinuxController
elif platform.system() == "Windows":
    TorController = WindowsController
else:
    raise NotImplementedError("Unsupported platform")

from tor.tor_socket import TorSocket