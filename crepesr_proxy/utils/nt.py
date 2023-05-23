import ctypes
import winreg
import subprocess
from shutil import which

def get_su():
    if which("sudo") or which("gsudo"):
        return "gsudo"
    return None

def is_root():
    return ctypes.windll.shell32.IsUserAnAdmin() != 0

def set_system_proxy(host: str, port: int):
    args = ["netsh", "winhttp", "set", "proxy", 
            f'{host}:{port}']
    su = get_su()
    if not is_root():
        if su:
            args.insert(0, su)
        else:
            raise OSError("Cannot set system proxy without root privileges.")
    subprocess.check_call(args=args)
    hkey = winreg.OpenKeyEx(
        winreg.HKEY_CURRENT_USER, 
        "Software\Microsoft\Windows\CurrentVersion\Internet Settings", 
        access=winreg.KEY_ALL_ACCESS
        )  # noqa: E501
    winreg.SetValueEx(hkey, "ProxyEnable", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(hkey, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
    winreg.CloseKey(hkey)

def unset_system_proxy(*args, **kwargs):
    # Compatible with Linux set_system_proxy
    args = ["netsh", "winhttp", "reset", "proxy"]
    su = get_su()
    if not is_root():
        if su:
            args.insert(0, su)
        else:
            raise OSError("Cannot unset system proxy without root privileges.")
    subprocess.check_call(args=args)
    hkey = winreg.OpenKeyEx(
        winreg.HKEY_CURRENT_USER, 
        "Software\Microsoft\Windows\CurrentVersion\Internet Settings", 
        access=winreg.KEY_ALL_ACCESS
        )  # noqa: E501
    winreg.SetValueEx(hkey, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    winreg.SetValueEx(hkey, "ProxyServer", 0, winreg.REG_SZ, "")
    winreg.CloseKey(hkey)
