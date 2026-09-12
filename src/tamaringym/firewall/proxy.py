"""
Domain-allowlist firewall for agent containers (adapted from ExploitGym).

Runs a Squid forward proxy bridging an **internal** Docker network (no
internet route) and the default bridge. Agent containers sit on the internal
network and can only reach the proxy — direct connections fail even if a
program ignores HTTP_PROXY, because there is no route out.

    Agent ──(tamaringym-internal, no internet)──▶ Squid ──(bridge)──▶ Internet
                                                       filtered by domain

The *run* proxy enforces the API-only allowlist (LLM endpoints; no web
search, no fetching published Tamarin proofs). An optional *install* proxy
(``FirewallProxyManager.for_install()``) forwards anywhere for a
pre-agent install phase; the evaluator disconnects the container from that
network before the agent runs.

    python -m tamaringym.firewall start --which run
    python -m tamaringym.firewall start --which install
    python -m tamaringym.firewall start --which both
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from docker.errors import APIError, NotFound

import docker

logger = logging.getLogger(__name__)

PROXY_CONTAINER_NAME = "tamaringym-proxy"
PROXY_IMAGE = "ubuntu/squid:latest"
PROXY_PORT = 13128
INTERNAL_NETWORK = "tamaringym-internal"

INSTALL_PROXY_CONTAINER_NAME = "tamaringym-install-proxy"
INSTALL_NETWORK = "tamaringym-install"
INSTALL_PROXY_PORT = 13129

DEFAULT_ALLOWLIST_PATH = Path(__file__).with_name("default_allowlist.txt")

DOMAIN_ALLOWLIST_CONTAINER_PATH = "/etc/squid/allowed_domains.txt"

SQUID_CONF_TEMPLATE = """\
# --- ProtocolBench domain-allowlist proxy ---

acl SSL_ports port 443
acl Safe_ports port 80 443
acl CONNECT method CONNECT

acl allowed_domains dstdomain "{domain_allowlist_path}"

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow CONNECT allowed_domains
http_access allow allowed_domains
http_access deny all

http_port {port}

cache deny all
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log
"""

ALLOW_ALL_SQUID_CONF_TEMPLATE = """\
# --- ProtocolBench install proxy (allow-all; pre-agent phase only) ---

acl SSL_ports port 1-65535
acl Safe_ports port 1-65535
acl CONNECT method CONNECT

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow all

http_port {port}

cache deny all
access_log /var/log/squid/access.log
cache_log /var/log/squid/cache.log
"""


def load_allowlist(path: str | Path) -> list[str]:
    """One domain per line; leading dot = domain + subdomains."""
    domains: list[str] = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            domains.append(line)
    return domains


class FirewallProxyManager:
    """Manages the Squid proxy container + its internal docker network."""

    def __init__(
        self,
        allowlist_path: str | Path | None = None,
        extra_domains: list[str] | None = None,
        proxy_image: str = PROXY_IMAGE,
        proxy_port: int = PROXY_PORT,
        container_name: str = PROXY_CONTAINER_NAME,
        network_name: str = INTERNAL_NETWORK,
        allow_all: bool = False,
        client: docker.DockerClient | None = None,
    ) -> None:
        self.allowlist_path = allowlist_path or DEFAULT_ALLOWLIST_PATH
        self.extra_domains = extra_domains or []
        self.proxy_image = proxy_image
        self.proxy_port = proxy_port
        self.container_name = container_name
        self.network_name = network_name
        self.allow_all = allow_all
        self._client = client

    @classmethod
    def for_install(cls, **kwargs) -> "FirewallProxyManager":
        kwargs.setdefault("container_name", INSTALL_PROXY_CONTAINER_NAME)
        kwargs.setdefault("network_name", INSTALL_NETWORK)
        kwargs.setdefault("proxy_port", INSTALL_PROXY_PORT)
        return cls(allow_all=True, **kwargs)

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    def _ensure_image(self) -> None:
        try:
            self.client.images.get(self.proxy_image)
        except NotFound:
            logger.info("pulling %s", self.proxy_image)
            self.client.images.pull(self.proxy_image)

    def _ensure_network(self) -> None:
        try:
            self.client.networks.get(self.network_name)
        except NotFound:
            self.client.networks.create(
                self.network_name,
                driver="bridge",
                internal=True,
                labels={"tamaringym.owner": "firewall"},
            )
            logger.info("created internal network %s", self.network_name)

    def _squid_conf(self) -> str:
        if self.allow_all:
            return ALLOW_ALL_SQUID_CONF_TEMPLATE.format(port=self.proxy_port)
        return SQUID_CONF_TEMPLATE.format(
            port=self.proxy_port,
            domain_allowlist_path=DOMAIN_ALLOWLIST_CONTAINER_PATH,
        )

    def start(self, recreate: bool = False) -> None:
        """Start (or reuse) the proxy container. Blocks until healthy."""
        self._ensure_image()
        self._ensure_network()
        try:
            existing = self.client.containers.get(self.container_name)
            if recreate:
                existing.remove(force=True)
            else:
                logger.info("reusing existing proxy %s", self.container_name)
                self._connect_network(existing)
                return
        except NotFound:
            pass

        allowlist_content = "\n".join(
            load_allowlist(self.allowlist_path) + self.extra_domains
        )
        import io
        import tarfile

        def _file_tar(name: str, content: str) -> bytes:
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as tar:
                data = content.encode()
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                info.mode = 0o644
                tar.addfile(info, io.BytesIO(data))
            return buf.getvalue()

        conf_tar = _file_tar("squid.conf", self._squid_conf())
        allowlist_tar = _file_tar(
            Path(DOMAIN_ALLOWLIST_CONTAINER_PATH).name,
            allowlist_content + "\n",
        )

        container = self.client.containers.run(
            self.proxy_image,
            name=self.container_name,
            detach=True,
            network=self.network_name,  # internal side
            labels={"tamaringym.owner": "firewall"},
            command=["squid", "-N", "-f", "/etc/squid/squid.conf"],
        )
        # bridge the proxy to the default network so it can reach the internet
        try:
            bridge = self.client.networks.get("bridge")
            bridge.connect(container)
        except APIError as e:
            logger.warning("could not bridge proxy to default network: %s", e)

        container.put_archive("/etc/squid", io.BytesIO(conf_tar))
        if not self.allow_all:
            container.put_archive("/etc/squid", io.BytesIO(allowlist_tar))
        container.restart()

        for _ in range(30):
            res = container.exec_run(["squid", "-k", "check"])
            if res.exit_code == 0:
                logger.info(
                    "proxy %s healthy on port %d", self.container_name, self.proxy_port
                )
                return
            time.sleep(1)
        raise RuntimeError(f"proxy {self.container_name} failed to become healthy")

    def _connect_network(self, container) -> None:
        try:
            self.client.networks.get(self.network_name)
        except NotFound:
            self._ensure_network()
        try:
            self.client.networks.get(self.network_name).connect(container)
        except APIError:
            pass  # already connected

    def stop(self) -> None:
        try:
            container = self.client.containers.get(self.container_name)
            container.remove(force=True)
            logger.info("proxy %s removed", self.container_name)
        except NotFound:
            pass

    # ── helpers for evaluators ────────────────────────────────────────────

    def connect(self) -> None:
        """Verify the proxy + network exist (start if needed)."""
        self.start()

    @property
    def host_gateway(self) -> str:
        """Address of the proxy as seen from agent containers.

        Agent containers live on the internal network and resolve the proxy
        container's name via docker's embedded DNS, so the container name is
        the stable address. The proxy is attached to that network in
        ``start()``; this property is deliberately docker-free so callers can
        compose env vars without a running daemon.
        """
        return self.container_name

    @property
    def proxy_url(self) -> str:
        return f"http://{self.host_gateway}:{self.proxy_port}"

    def env_vars(self) -> dict[str, str]:
        """Proxy environment variables for docker exec into agent containers."""
        url = self.proxy_url
        return {
            "HTTP_PROXY": url,
            "HTTPS_PROXY": url,
            "http_proxy": url,
            "https_proxy": url,
            "NO_PROXY": "localhost,127.0.0.1",
            "no_proxy": "localhost,127.0.0.1",
        }


def main() -> None:
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    ap = argparse.ArgumentParser(
        description="manage the ProtocolBench firewall proxies"
    )
    ap.add_argument("action", choices=["start", "stop", "status"])
    ap.add_argument("--which", choices=["run", "install", "both"], default="both")
    ap.add_argument("--extra-domains", nargs="*", default=[])
    args = ap.parse_args()

    managers = []
    if args.which in ("run", "both"):
        managers.append(FirewallProxyManager(extra_domains=args.extra_domains))
    if args.which in ("install", "both"):
        managers.append(FirewallProxyManager.for_install())

    for m in managers:
        if args.action == "start":
            m.start()
            print(f"{m.container_name}: {m.proxy_url} network={m.network_name}")
        elif args.action == "stop":
            m.stop()
        elif args.action == "status":
            try:
                c = m.client.containers.get(m.container_name)
                print(f"{m.container_name}: running ({c.status}) {m.proxy_url}")
            except NotFound:
                print(f"{m.container_name}: not running")


if __name__ == "__main__":
    main()
