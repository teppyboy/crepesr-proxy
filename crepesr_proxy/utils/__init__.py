import platform
import socket
from contextlib import closing

match platform.system():
    case "Windows":
        from .nt import *  # noqa: F403
    case "Linux":
        from .linux import *  # noqa: F403


def get_free_port() -> int:
    """
    Gets a free port to use with mitmproxy

    Source: https://stackoverflow.com/a/45690594/13671777

    Returns:
        An integer representing the free port.
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return s.getsockname()[1]
