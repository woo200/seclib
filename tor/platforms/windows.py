import subprocess
import shutil

from tor.controller import Controller

class WindowsController(Controller):
    def __init__(self):
        raise NotImplementedError("Windows Tor controller not implemented")
