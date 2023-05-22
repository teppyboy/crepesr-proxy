import asyncio
import logging
import threading
import socket
import requests
import platform
import subprocess
from pathlib import Path
from shutil import which
from tempfile import NamedTemporaryFile
from mitmproxy.http import HTTPFlow
from contextlib import closing
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster
from crepesr_proxy import utils
from crepesr_proxy.proxy.exceptions import CertificateInstallError


class Sniffer:
    # Taken from the Google Docs file.
    BLACKLIST = [".yuanshen.com", ".hoyoverse.com", ".mihoyo.com", "starrails.com", 
                 ".kurogame.com", "zenlesszonezero.com", "api.g3.proletariat.com", 
                 "west.honkaiimpact3.com"]
    SERVER = "sr.crepe.moe"
    def __init__(self) -> None:
        self._logger = logging.getLogger("crepesr-proxy.proxy.sniffer")
        self._logger.info("Sniffer started.")

    def request(self, flow: HTTPFlow):
        host = flow.request.pretty_host
        self._logger.debug("Request: {}".format(host))
        if any([host.endswith(x) for x in self.BLACKLIST]):
            self._logger.info("Request redirected: {}".format(host))
            flow.request.host = self.SERVER

        if "overseauspider.yuanshen.com" in flow.request.host:
            self._logger.info("Logging server blocked: {}".format(host))
            flow.kill()


class ProxyManager:
    def __init__(self):
        """
        Manage mitmproxy to create necessary proxy for the app to work.
        """
        self._mitm = None
        self._loop, self._thread = self._create_loop()
        self.proxy_port = 13168
        self.proxy_host = "127.0.0.1"
        self._mitm_options = self._create_mitmproxy_options()
        self._logger = logging.getLogger("crepesr-proxy.proxy")

    @staticmethod
    def _get_free_port() -> int:
        """
        Gets a free port to use with mitmproxy

        Source: https://stackoverflow.com/a/45690594/13671777

        Returns:
            An integer representing the free port.
        """
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(('', 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]

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

    def _create_mitmproxy_options(self):
        """
        Create a new configuration for mitmproxy
        """
        options = Options(
            listen_host=self.proxy_host,
            listen_port=self.proxy_port,
            ssl_insecure=True,
            upstream_cert=False
        )
        return options

    async def _create_mitmdump(self):
        # DumpMaster require an existing loop so we use async here.
        if self._mitm:
            self._logger.warning("mitmproxy is already created")
            return
        self._mitm = DumpMaster(options=self._mitm_options)
        self._mitm.addons.add(Sniffer())
        self._logger.debug("mitmproxy created")

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
            "http": "http://{}:{}".format(self.proxy_host, self.proxy_port),
            "https": "http://{}:{}".format(self.proxy_host, self.proxy_port)
        }
        try:
            requests.get("https://google.com", proxies=proxies, 
                        verify=self._get_system_cert_path())
        except requests.exceptions.SSLError:
            return False
        return True
    
    def _get_su(self):
        if which("pkexec"):
            return "pkexec"
        elif which("sudo"):
            return "sudo"
        else:
            raise FileNotFoundError("No su wrapper found.")

    def _install_certificate_linux(self):
        rsp = requests.get("http://mitm.it/cert/pem", proxies = {
            "http": "http://{}:{}".format(self.proxy_host, self.proxy_port),
            "https": "http://{}:{}".format(self.proxy_host, self.proxy_port)
        })
        file = NamedTemporaryFile(suffix=".pem")
        file.write(rsp.content)
        file.flush()
        # This method works in Arch Linux, not sure about other distros.
        try:
            if utils.is_root():
                subprocess.check_call(["trust", "anchor", "--store", file.name])
                subprocess.check_call(["update-ca-trust"])
            else:
                subprocess.check_call([self._get_su(), "trust", "anchor", "--store", 
                                       file.name])
                subprocess.check_call([self._get_su(), "update-ca-trust"])
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            raise CertificateInstallError("Failed to install certificate: {}".format(e))

    def _install_certificate_nt(self):
        rsp = requests.get("http://mitm.it/cert/cer", proxies = {
            "http": "http://{}:{}".format(self.proxy_host, self.proxy_port),
            "https": "http://{}:{}".format(self.proxy_host, self.proxy_port)
        })
        with NamedTemporaryFile(suffix=".p12", delete=False) as file:
            file.write(rsp.content)
            file.flush()
        self._logger.debug("Certificate file: {}".format(file.name))
        try:
            if utils.is_root():
                subprocess.check_call(["certutil.exe", "-addstore", "root", file.name])
            else:
                subprocess.check_call([self._get_su(), "certutil.exe", "-addstore", 
                                       "root", file.name])
        except subprocess.CalledProcessError as e:
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

    def _set_system_proxy_nt(self):
        subprocess.check_call(["netsh", "winhttp", "set", "proxy", 
                        f'proxy-server="http={self.proxy_host}:{self.proxy_port};https={self.proxy_host}:{self.proxy_port}"',
                        'bypass-list="localhost"'])

    def _unset_system_proxy_nt(self):
        subprocess.check_call(["netsh", "winhttp", "reset", "proxy"])

    def set_system_proxy(self):
        match platform.system():
            case "Linux":
                raise NotImplementedError("Linux is not supported yet.")
            case "Windows":
                self._set_system_proxy_nt()
            case "Darwin":
                raise NotImplementedError("MacOS is not supported yet.")
            
    def unset_system_proxy(self):
        match platform.system():
            case "Linux":
                raise NotImplementedError("Linux is not supported yet.")
            case "Windows":
                self._unset_system_proxy_nt()
            case "Darwin":
                raise NotImplementedError("MacOS is not supported yet.")