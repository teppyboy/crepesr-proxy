import ctypes

def is_root():
    return ctypes.windll.shell32.IsUserAnAdmin() != 0
