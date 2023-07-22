import asyncio
import logging
import threading
import requests
import platform
import subprocess
import os
from ast import literal_eval
from enum import Enum
from pathlib import Path
from tempfile import NamedTemporaryFile
from mitmproxy.http import HTTPFlow, Response
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from crepesr_proxy import utils
from crepesr_proxy.proxy.exceptions import (
    CertificateInstallError,
    SetSystemProxyError,
    UnsetSystemProxyError,
)


class YSSniffer:
    # Use Grasscutter official server
    HOST = os.getenv("SERVER_ADDRESS", "game.grasscutter.io")
    USE_SSL = os.getenv("USE_SSL", "true").lower() == "true"
    PORT = int(os.getenv("SERVER_PORT", "443"))

    def __init__(self) -> None:
        self._logger = logging.getLogger("crepesr-proxy.proxy.ys.sniffer")
        self._logger.info("Server address: {}".format(self.HOST))
        self._logger.info("Server port: {}".format(self.PORT))
        self._logger.info("Use SSL: {}".format(self.USE_SSL))
        self._logger.info("YS Sniffer started.")

    def request(self, flow: HTTPFlow):
        host = flow.request.pretty_host
        # Cultivation design to make it work with Grasscutter OAuth.
        if (
            host.endswith(".mihoyo.com")
            or host.endswith(".yuanshen.com")
            or host.endswith(".hoyoverse.com")
        ):
            self._logger.info("Redirected: {}".format(host))
            if self.USE_SSL:
                flow.request.scheme = "https"
            else:
                flow.request.scheme = "http"
            flow.request.host = self.HOST
            flow.request.port = self.PORT


class SRSniffer:
    # Taken from the Google Docs file.
    BLACKLIST = [
        ".yuanshen.com",
        ".hoyoverse.com",
        ".mihoyo.com",
        "starrails.com",
        ".kurogame.com",
        "zenlesszonezero.com",
        "api.g3.proletariat.com",
        "west.honkaiimpact3.com",
    ]
    HOST = os.getenv("SERVER_ADDRESS", "sr.crepe.moe")
    USE_SSL = literal_eval(f"\"{os.getenv('USE_SSL', 'None').title()}\"")
    PORT = literal_eval(os.getenv("SERVER_PORT", "None"))

    def __init__(self) -> None:
        self._logger = logging.getLogger("crepesr-proxy.proxy.sr.sniffer")
        self._logger.info("Server address: {}".format(self.HOST))
        self._logger.info("Server port: {}".format(self.PORT))
        self._logger.info("SR Sniffer started.")

    def request(self, flow: HTTPFlow):
        host = flow.request.pretty_host
        if "overseauspider.yuanshen.com" in flow.request.host:
            self._logger.info("Logging server blocked: {}".format(host))
            flow.kill()
            flow.response = Response.make(404)
            return
        if any([host.endswith(x) for x in self.BLACKLIST]):
            self._logger.info("Redirected: {}".format(host))
            flow.request.host = self.HOST
            if self.USE_SSL is not None:
                if self.USE_SSL:
                    flow.request.scheme = "https"
                else:
                    flow.request.scheme = "http"
            if isinstance(self.PORT, int):
                flow.request.port = self.PORT


class ProxyType(Enum):
    SR = 0
    YS = 1


class Proxy:
    def __init__(self, proxy_type: ProxyType = ProxyType.SR):
        """
        Manage mitmproxy to create necessary proxy for the app to work.
        """
        self._mitm = None
        self._loop, self._thread = self._create_loop()
        self._proxy_type = proxy_type
        self.proxy_port = 13168
        self.proxy_host = "127.0.0.1"
        self._proxy_host = (
            "127.0.0.1" if self.proxy_host == "0.0.0.0" else self.proxy_host
        )
        self._mitm_options = self._create_mitmproxy_options()
        self._set_logger()

    def _set_logger(self):
        match self._proxy_type:
            case ProxyType.SR:
                self._logger = logging.getLogger("crepesr-proxy.proxy.sr")
            case ProxyType.YS:
                self._logger = logging.getLogger("crepesr-proxy.proxy.ys")

    @staticmethod
    def _create_loop():
        """
        Creates a new event loop.

        Returns:
            A new event loop that is started and run forever.
        """
        loop = asyncio.new_event_loop()
        # Daemonized Thread to not block the program.
        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()
        asyncio.set_event_loop(loop)
        return loop, thread

    @property
    def proxy_type(self):
        return self._proxy_type

    @proxy_type.setter
    def proxy_type(self, value: ProxyType):
        if self._mitm is not None:
            raise RuntimeError(
                "Cannot change proxy type after mitmproxy is created. "
                + "You need to stop the proxy first."
            )
        self._proxy_type = value
        self._set_logger()

    def _create_mitmproxy_options(self):
        """
        Create a new configuration for mitmproxy
        """
        options = Options(
            listen_host=self.proxy_host,
            listen_port=self.proxy_port,
            ssl_insecure=True,
            upstream_cert=False,
        )
        return options

    async def _create_mitmdump(self):
        # DumpMaster require an existing loop so we use async here.
        if self._mitm:
            self._logger.warning("mitmproxy is already created")
            return
        self._mitm = DumpMaster(options=self._mitm_options)
        match self._proxy_type:
            case ProxyType.SR:
                self._mitm.addons.add(SRSniffer())
            case ProxyType.YS:
                self._mitm.addons.add(YSSniffer())
        self._logger.debug("mitmproxy instance created")

    async def _run_mitmdump(self, port):
        if not self._mitm:
            await self._create_mitmdump()
        if port != 0:
            self.set_proxy_port(port)
        await self._mitm.run()

    def create_proxy(self):
        """
        Creates a new proxy.

        It is optional to use this function unless you want to set mitmproxy port
        before starting proxy.

        Returns:
            A future object that can be used to wait for the proxy to be created.
        """
        return asyncio.run_coroutine_threadsafe(self._create_mitmdump(), self._loop)

    def set_proxy_port(self, port: int):
        """
        Sets the proxy port to the specified one.

        Args:
            port: Port for the proxy to use, must be free.
        """
        if not self._mitm:
            proxy = self.create_proxy()
            # Blocking so we can wait until the proxy is created.
            proxy.result()
        self._mitm.options.update(listen_port=port)

    def start_proxy(self, port: int = 0):
        """
        Starts mitmproxy.
        """
        asyncio.run_coroutine_threadsafe(self._run_mitmdump(port), self._loop)

    def stop_proxy(self):
        if not self._mitm:
            logging.warning("mitmproxy hasn't been created yet.")
            return
        self._mitm.shutdown()
        self._loop.stop()
        self._loop, self._thread = self._create_loop()
        del self._mitm

    def _get_system_cert_path(self):
        match platform.system():
            case "Linux":
                return "/etc/ssl/certs/ca-certificates.crt"
            case "Windows":
                return True
            case "Darwin":
                raise NotImplementedError("MacOS is not supported yet.")

    def is_certificate_installed(self) -> bool:
        proxies = {
            "http": "http://{}:{}".format(self._proxy_host, self.proxy_port),
            "https": "http://{}:{}".format(self._proxy_host, self.proxy_port),
        }
        try:
            requests.get(
                "https://google.com",
                proxies=proxies,
                verify=self._get_system_cert_path(),
            )
        except requests.exceptions.SSLError:
            return False
        return True

    def _install_certificate_linux(self):
        rsp = requests.get(
            "http://mitm.it/cert/pem",
            proxies={
                "http": "http://{}:{}".format(self._proxy_host, self.proxy_port),
                "https": "http://{}:{}".format(self.proxy_host, self.proxy_port),
            },
        )
        file = NamedTemporaryFile(suffix=".pem")
        file.write(rsp.content)
        file.flush()
        # This method works in Arch Linux, not sure about other distros.
        try:
            args1 = ["trust", "anchor", "--store", file.name]
            args2 = ["update-ca-trust"]
            su = utils.get_su()
            if not utils.is_root():
                if su:
                    args1.insert(0, su)
                    args2.insert(0, su)
                else:
                    raise OSError("Cannot install certificate without root privileges.")
            subprocess.check_call(args=args1)
            subprocess.check_call(args=args2)
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
            raise CertificateInstallError("Failed to install certificate: {}".format(e))

    def _install_certificate_nt(self):
        rsp = requests.get(
            "http://mitm.it/cert/cer",
            proxies={
                "http": "http://{}:{}".format(self._proxy_host, self.proxy_port),
                "https": "http://{}:{}".format(self.proxy_host, self.proxy_port),
            },
        )
        with NamedTemporaryFile(suffix=".p12", delete=False) as file:
            file.write(rsp.content)
            file.flush()
        self._logger.debug("Certificate file: {}".format(file.name))
        try:
            if utils.is_root():
                subprocess.check_call(["certutil.exe", "-addstore", "root", file.name])
            else:
                subprocess.check_call(
                    [utils.get_su(), "certutil.exe", "-addstore", "root", file.name]
                )
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise CertificateInstallError("Failed to install certificate: {}".format(e))
        finally:
            Path(file.name).unlink(missing_ok=True)

    def install_certificate(self):
        match platform.system():
            case "Linux":
                self._install_certificate_linux()
            case "Windows":
                self._install_certificate_nt()
            case "Darwin":
                raise NotImplementedError("MacOS is not supported yet.")

    def set_system_proxy(self):
        try:
            match platform.system():
                case "Linux":
                    utils.set_system_proxy(self.proxy_host, self.proxy_port)
                case "Windows":
                    utils.set_system_proxy(self.proxy_host, self.proxy_port)
                case "Darwin":
                    raise SetSystemProxyError("MacOS is not supported yet.")
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
            raise SetSystemProxyError("Failed to set system proxy") from e
        except SetSystemProxyError:
            raise

    def unset_system_proxy(self):
        try:
            match platform.system():
                case "Linux":
                    utils.unset_system_proxy(self.proxy_host, self.proxy_port)
                case "Windows":
                    utils.unset_system_proxy()
                case "Darwin":
                    raise UnsetSystemProxyError("MacOS is not supported yet.")
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
            raise UnsetSystemProxyError("Failed to set system proxy") from e
        except UnsetSystemProxyError:
            raise

    def set_server_address(self, address, port: int = 0):
        """
        Sets the server address for the proxy to redirect to.
        """
        if self._mitm is not None:
            raise RuntimeError(
                "Cannot change proxy address after mitmproxy is created."
                + " You need to stop the proxy first."
            )
        if self._proxy_type == ProxyType.SR:
            SRSniffer.HOST = address
            if port != 0:
                SRSniffer.PORT = port
        elif self._proxy_type == ProxyType.YS:
            YSSniffer.HOST = address
            if port != 0:
                YSSniffer.PORT = port

    def set_server_port(self, port):
        """
        Sets the server port for the proxy to redirect to.
        """
        if self._mitm is not None:
            raise RuntimeError(
                "Cannot change proxy address after mitmproxy is created."
                + " You need to stop the proxy first."
            )
        if self._proxy_type == ProxyType.SR:
            SRSniffer.PORT = port
        elif self._proxy_type == ProxyType.YS:
            YSSniffer.PORT = port

    def get_server_address(self):
        """
        Gets the server address for the proxy to redirect to.
        """
        if self._proxy_type == ProxyType.SR:
            return SRSniffer.HOST, SRSniffer.PORT
        elif self._proxy_type == ProxyType.YS:
            return YSSniffer.HOST, YSSniffer.PORT
