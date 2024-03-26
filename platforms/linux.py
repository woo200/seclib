import subprocess
import os 

tor_binary = "tor/src/app/tor"

def elevate():
    print("Installing Tor... Please enter your password...")
    subprocess.run(["sudo", "echo"])

def generate_torrc(port):
    with open("torrc", "w") as f:
        f.write(f"""HiddenServiceDir {os.getcwd()}/hidden_service/
HiddenServicePort {port} 127.0.0.1:{port}
SocksPort 9051""")

def install_tor():
    if os.path.exists("tor/src/app/tor"):
        return
    
    elevate()
    packages = [
        'git', 
        'build-essential', 
        'automake', 
        'libevent-dev', 
        'libssl-dev', 
        'zlib1g-dev'
    ]
    subprocess.run(["sudo", "apt-get", "install", "-y", *packages])
    if not os.path.exists("tor"):
        subprocess.run(["git", "clone", "https://git.torproject.org/tor.git"])
    
    subprocess.run(["chmod", "-R", "777", "*"], cwd="tor")
    subprocess.run(["sh", "./autogen.sh"], cwd="tor")
    subprocess.run(["sh", "./configure", "--disable-asciidoc"], cwd="tor")
    subprocess.run(["make"], cwd="tor")
