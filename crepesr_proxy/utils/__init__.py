import platform

match platform.system():
    case "Windows":
        from .nt import *  # noqa: F403
    case "Linux":
        from .linux import *  # noqa: F403
