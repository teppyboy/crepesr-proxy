from crepesr_proxy.proxy import Proxy, ProxyType
from crepesr_proxy.proxy.exceptions import (
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
    proxy_manager = Proxy()
    # I'm too lazy to use argparse
    for arg in sys.argv:
        if arg.startswith("--proxy-ip="):
            proxy_manager.proxy_host = arg.split("=")[1]
        elif arg.startswith("--proxy-port="):
            proxy_manager.set_proxy_port(arg.split("=")[1])
        elif arg.startswith("--proxy-server="):
            proxy_manager.proxy_host = arg.split("=")[1].split(":")[0]
            try:
                port = arg.split("=")[1].split(":")[1]
            except IndexError:
                pass
            else:
                proxy_manager.set_proxy_port(port=port)
        elif arg.startswith("--server-address="):
            proxy_manager.set_server_address(arg.split("=")[1].split(":")[0])
            try:
                port = arg.split("=")[1].split(":")[1]
            except IndexError:
                pass
            else:
                proxy_manager.set_server_port(port=port)
        elif arg.startswith("--server-port="):
            proxy_manager.set_server_port(arg.split("=")[1])
        elif arg.startswith("--no-set-system-proxy"):
            sys_proxy_set = False
        elif arg.startswith("--ys") or arg.startswith("--genshin"):
            proxy_manager.proxy_type = ProxyType.YS
        elif arg.startswith("--help"):
            print(
                """Usage: crepesr-proxy [OPTIONS]
Options:
    --proxy-ip=IP             Set the proxy IP address.
    --proxy-port=PORT         Set the proxy port.
    --proxy-server=SERVER     Set the proxy server (IP:PORT).
    --server-address=SERVER   Set the server address (IP:PORT (optional)).
    --server-port=PORT        Set the server port.
    --no-set-system-proxy     Do not set the system proxy.
    --ys                      Set the proxy mode to Genshin.
    --genshin                 Alias to --ys.
    --help                    Show this message and exit."""
            )
            return

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
    server_address, server_port = proxy_manager.get_server_address()
    logger.info("Server address: {}".format(server_address))
    logger.info("Server port (optional): {}".format(server_port))
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
