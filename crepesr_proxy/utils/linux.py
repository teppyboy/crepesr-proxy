import os
import subprocess
from shutil import which

def is_root():
    return os.getuid() == 0

def get_su():
    if which("pkexec"):
        return "pkexec"
    elif which("sudo"):
        return "sudo"
    elif which("doas"):
        return "doas"
    else:
        return None

def set_system_proxy(host: str, port: int):
    if host not in ["127.0.0.1", "localhost"]:
        raise NotImplementedError("Only localhost is supported for now.")
    args = ["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-m", "owner", "!", 
            "--uid-owner", "root", "-m", "multiport", "--dports", "80,443", "-j", 
            "REDIRECT", "--to-port", str(port)]
    su = get_su()
    if not is_root():
        if su:
            args.insert(0, su)
        else:
            raise OSError("Cannot set system proxy without root privileges.")
    subprocess.check_call(args=args)

def unset_system_proxy(host: str, port: int):
    if host not in ["127.0.0.1", "localhost"]:
        raise NotImplementedError("Only localhost is supported for now.")
    args = ["iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-m", "owner", "!", 
            "--uid-owner", "root", "-m", "multiport", "--dports", "80,443", "-j", 
            "REDIRECT", "--to-port", str(port)]
    su = get_su()
    if not is_root():
        if su:
            args.insert(0, su)
        else:
            raise OSError("Cannot unset system proxy without root privileges.")
    subprocess.check_call(args=args)

