import os

def is_root():
    return os.getuid() == 0

def set_system_proxy(host: str, port: int):
    pass

def unset_system_proxy():
    pass
