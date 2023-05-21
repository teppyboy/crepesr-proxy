from .proxy import ProxyManager
import time
import sys
import logging

logger = logging.getLogger("crepesr-proxy")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


def main():
    logging.getLogger("mitmproxy").setLevel(logging.ERROR)
    logger.info("Creating new mitmproxy instance...")
    proxy_manager = ProxyManager()
    logger.info("Starting proxy...")
    proxy_manager.start_proxy()
    logger.info("Checking for certificate installation...")
    if not proxy_manager.is_certificate_installed():
        logger.info("Certificate not installed, installing...")
        proxy_manager.install_certificate()
    else:
        logger.info("Certificate already installed.")
    logger.info("Proxy started.")
    logger.info("Press Ctrl+C to stop proxy.")
    try:
        while True:
            time.sleep(9e5)
    except KeyboardInterrupt:
        logging.info("Stopping proxy...")
        proxy_manager.stop_proxy()
        logging.info("Proxy stopped.")

main()
