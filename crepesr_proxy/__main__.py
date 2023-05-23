from .proxy import ProxyManager
from .proxy.exceptions import (
    CertificateInstallError,
    SetSystemProxyError,
    UnsetSystemProxyError,
)
import time
import sys
import logging

logger = logging.getLogger("crepesr-proxy")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("[%(asctime)s] [%(name)s] [%(levelname)s]: %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


def main():
    sys_proxy_set = True
    proxy_manager = ProxyManager()
    for arg in sys.argv:
        if arg.startswith("--ip="):
            proxy_manager.proxy_host = arg.split("=")[1]
        elif arg.startswith("--port="):
            proxy_manager.set_proxy_port(arg.split("=")[1])
        elif arg.startswith("--address="):
            proxy_manager.proxy_host = arg.split("=")[1].split(":")[0]
            try:
                port = arg.split("=")[1].split(":")[1]
            except IndexError:
                pass
            else:
                proxy_manager.set_proxy_port(port=port)
        elif arg.startswith("--no-set-system-proxy"):
            sys_proxy_set = False
    logger.info("Creating new mitmproxy instance...")
    logging.getLogger("mitmproxy").setLevel(logging.ERROR)
    logger.info("Starting proxy...")
    proxy_manager.start_proxy()
    logger.info("Checking for certificate installation...")
    if not proxy_manager.is_certificate_installed():
        logger.info("Certificate not installed, installing...")
        try:
            proxy_manager.install_certificate()
        except CertificateInstallError as e:
            logger.error(e)
    else:
        logger.info("Certificate already installed.")
    if sys_proxy_set:
        try:
            logger.info("Setting system proxy...")
            proxy_manager.set_system_proxy()
        except SetSystemProxyError as e:
            logger.error(e)
            sys_proxy_set = False
    logger.info(
        "Proxy started at http://{}:{}".format(
            proxy_manager.proxy_host, proxy_manager.proxy_port
        )
    )
    logger.info("Press Ctrl+C to stop proxy.")
    try:
        while True:
            time.sleep(1e6)
    except KeyboardInterrupt:
        print("a")
        pass
    if sys_proxy_set:
        try:
            logger.info("Unsetting system proxy...")
            proxy_manager.unset_system_proxy()
        except UnsetSystemProxyError as e:
            logger.error(e)
    logger.info("Stopping proxy...")
    proxy_manager.stop_proxy()
    logger.info("Proxy stopped.")


main()
