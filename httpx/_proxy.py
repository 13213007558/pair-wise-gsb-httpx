from __future__ import annotations

import dataclasses
import ipaddress
import os
import re
import sys
import typing

from ._config import Proxy
from ._urls import URL


__all__ = [
    "ProxyDecision",
    "ProxyPolicy",
]


DEFAULT_PORTS = {"http": 80, "https": 443}
SCHEMES = {"all", "http", "https"}
DOMAIN_REGEX = re.compile(
    r"^(?:\*|[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)"
    r"(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*\.?$"
)


class _UseClientDefault:
    pass


USE_CLIENT_DEFAULT = _UseClientDefault()
UseClientDefaultType = typing.Union[str, URL, Proxy, None, bool, _UseClientDefault]


def canonical_host(url: URL) -> str:
    host = url.raw_host.decode("ascii").lower()
    if host.endswith("."):
        host = host[:-1]
    try:
        return str(ipaddress.ip_address(host)).lower()
    except ValueError:
        return host


def effective_port(url: URL) -> int | None:
    if url.port is not None:
        return url.port
    return DEFAULT_PORTS.get(url.scheme)


def _valid_port(value: str, *, token: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise ValueError(f"Invalid NO_PROXY token {token!r}: port must be an integer")
    if not 1 <= port <= 65535:
        raise ValueError(
            f"Invalid NO_PROXY token {token!r}: port must be between 1 and 65535"
        )
    return port


def _encode_domain(host: str, *, token: str) -> str:
    try:
        import idna

        encoded = idna.encode(host, uts46=True).decode("ascii")
    except Exception:
        raise ValueError(f"Invalid NO_PROXY token {token!r}: invalid hostname")
    return encoded.lower()


@dataclasses.dataclass(frozen=True)
class NoProxyRule:
    token: str
    scheme: str
    host: str
    port: int | None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    subdomains_only: bool = False

    @classmethod
    def parse(cls, token: str) -> NoProxyRule:
        original = token
        token = token.strip()
        if not token:
            raise ValueError("NO_PROXY tokens must not be empty")

        scheme = "all"
        rest = token
        if "://" in token:
            scheme_value, separator, rest = token.partition("://")
            scheme_value = scheme_value.strip().lower()
            if separator and scheme_value not in SCHEMES:
                raise ValueError(
                    "Invalid NO_PROXY token "
                    f"{original!r}: scheme must be http, https, or all"
                )
            scheme = scheme_value
            if any(char in rest for char in "/?#"):
                raise ValueError(
                    "Invalid NO_PROXY token "
                    f"{original!r}: path, query, or fragment is not allowed"
                )

        host_port = rest
        if host_port.startswith("["):
            closing = host_port.find("]")
            if closing == -1:
                raise ValueError(
                    "Invalid NO_PROXY token "
                    f"{original!r}: missing closing ']' in IPv6 literal"
                )
            host_value = host_port[1:closing]
            suffix = host_port[closing + 1 :]
            port = None
            network = None
            network_text = host_value
            if "/" in host_value and suffix.startswith("/"):
                raise ValueError(
                    f"Invalid NO_PROXY token {original!r}: malformed IPv6 CIDR literal"
                )
            if suffix.startswith("/"):
                prefix_text, separator, port_text = suffix[1:].partition(":")
                network_text = f"{host_value}/{prefix_text}"
                if separator:
                    port = _valid_port(port_text, token=original)
            elif suffix:
                if not suffix.startswith(":") or ":" in suffix[1:]:
                    raise ValueError(
                        "Invalid NO_PROXY token "
                        f"{original!r}: malformed IPv6 literal or port"
                    )
                port = _valid_port(suffix[1:], token=original)
            if "/" in network_text:
                try:
                    network = ipaddress.ip_network(network_text, strict=True)
                except ValueError:
                    raise ValueError(
                        "Invalid NO_PROXY token "
                        f"{original!r}: invalid IPv6 CIDR literal"
                    )
                host_value = str(network.network_address)
            if network is None:
                try:
                    address = ipaddress.IPv6Address(host_value)
                except ValueError:
                    raise ValueError(
                        f"Invalid NO_PROXY token {original!r}: invalid IPv6 literal"
                    )
                host_value = str(address).lower()
            else:
                host_value = str(network.network_address).lower()
            return cls(
                token=original,
                scheme=scheme,
                host=host_value,
                port=port,
                network=network,
            )

        if "/" in host_port:
            host_value, separator, port_value = host_port.partition("/")
            if not host_value:
                raise ValueError(
                    f"Invalid NO_PROXY token {original!r}: missing IP address"
                )
            prefix_text, port_separator, actual_port = port_value.partition(":")
            if (
                not prefix_text
                or "/" in port_value
                or (not port_separator and actual_port)
            ):
                raise ValueError(
                    f"Invalid NO_PROXY token {original!r}: invalid CIDR literal"
                )
            try:
                network_text = f"{host_value}/{prefix_text}"
                network = ipaddress.ip_network(network_text, strict=True)
            except ValueError:
                raise ValueError(
                    f"Invalid NO_PROXY token {original!r}: invalid CIDR literal"
                )
            port = None
            if port_separator:
                port = _valid_port(actual_port, token=original)
            return cls(
                token=original,
                scheme=scheme,
                host=str(network.network_address).lower(),
                port=port,
                network=network,
            )

        subdomains_only = host_port.startswith(".")
        if subdomains_only:
            host_port = host_port[1:]
        if not host_port:
            raise ValueError(f"Invalid NO_PROXY token {original!r}: missing hostname")

        if host_port.count(":") > 1:
            if "/" in host_port:
                try:
                    network = ipaddress.ip_network(host_port, strict=True)
                except ValueError:
                    raise ValueError(
                        "Invalid NO_PROXY token "
                        f"{original!r}: invalid IPv6 CIDR literal"
                    ) from None
                return cls(
                    token=original,
                    scheme=scheme,
                    host=str(network.network_address).lower(),
                    port=None,
                    network=network,
                )
            try:
                address = ipaddress.IPv6Address(host_port)
            except ValueError:
                raise ValueError(
                    "Invalid NO_PROXY token "
                    f"{original!r}: IPv6 literals with a port must use square brackets"
                ) from None
            prefix, _, suffix = host_port.rpartition(":")
            try:
                port_value = int(suffix)
            except ValueError:
                port_value = 0
            if 1 <= port_value <= 65535:
                try:
                    ipaddress.IPv6Address(prefix)
                except ValueError:
                    pass
                else:
                    raise ValueError(
                        "Invalid NO_PROXY token "
                        f"{original!r}: IPv6 literals with a port must use "
                        "square brackets"
                    )
            return cls(
                token=original,
                scheme=scheme,
                host=str(address).lower(),
                port=None,
            )

        host_value, separator, port_text = host_port.partition(":")
        port = _valid_port(port_text, token=original) if separator else None
        host_value = host_value.strip().lower().rstrip(".")

        if host_value == "*":
            if subdomains_only:
                raise ValueError(
                    f"Invalid NO_PROXY token {original!r}: ambiguous wildcard"
                )
            return cls(
                token=original,
                scheme=scheme,
                host="*",
                port=port,
            )

        if host_value.startswith("*."):
            domain = host_value[2:]
            if "*" in domain or not DOMAIN_REGEX.fullmatch(domain):
                raise ValueError(
                    "Invalid NO_PROXY token "
                    f"{original!r}: ambiguous wildcard hostname"
                )
            return cls(
                token=original,
                scheme=scheme,
                host=_encode_domain(domain, token=original),
                port=port,
                subdomains_only=True,
            )

        try:
            address = ipaddress.ip_address(host_value)
        except ValueError:
            if "*" in host_value or not DOMAIN_REGEX.fullmatch(host_value):
                raise ValueError(
                    "Invalid NO_PROXY token "
                    f"{original!r}: ambiguous or invalid hostname"
                )
            host_value = _encode_domain(host_value, token=original)
        else:
            host_value = str(address).lower()

        return cls(
            token=original,
            scheme=scheme,
            host=host_value,
            port=port,
            subdomains_only=subdomains_only,
        )

    def matches(self, url: URL) -> bool:
        if self.scheme != "all" and self.scheme != url.scheme:
            return False

        host = canonical_host(url)
        if self.host == "*":
            return self.port is None or self.port == effective_port(url)
        if self.network is not None:
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                return False
            if not (
                self.network.version == address.version and address in self.network
            ):
                return False
            return self.port is None or self.port == effective_port(url)
        if host == self.host:
            if self.subdomains_only:
                return False
            return self.port is None or self.port == effective_port(url)
        if host.endswith("." + self.host):
            return self.port is None or self.port == effective_port(url)
        return False


@dataclasses.dataclass(frozen=True)
class ProxyDecision:
    proxy: typing.Any
    direct: bool
    reason: str
    rule: str | None = None
    source: str = "default"
    connect: str | None = None
    authenticated: bool = False

    @classmethod
    def direct_connection(cls, reason: str, **kwargs: typing.Any) -> ProxyDecision:
        return cls(proxy=None, direct=True, reason=reason, **kwargs)

    @classmethod
    def via_proxy(
        cls, proxy: Proxy, reason: str, **kwargs: typing.Any
    ) -> ProxyDecision:
        connect_line = None
        url: URL | None = kwargs.pop("url", None)
        if (
            proxy.url.scheme in ("http", "https")
            and url is not None
            and url.scheme == "https"
        ):
            host = canonical_host(url)
            if ":" in host:
                host = f"[{host}]"
            port = effective_port(url)
            if port is None:
                raise ValueError("Cannot CONNECT to a URL without a known port")
            connect_line = f"CONNECT {host}:{port} HTTP/1.1"
        return cls(
            proxy=proxy,
            direct=False,
            reason=reason,
            connect=connect_line,
            authenticated=proxy.raw_auth is not None
            or "proxy-authorization" in proxy.headers,
            **kwargs,
        )

    def connect_line(self, url: URL) -> str | None:
        return self.connect


ProxyRule = typing.Union[str, URL, Proxy, None]
ProxyRules = typing.Mapping[str, ProxyRule]


class ProxyPolicy:
    def __init__(
        self,
        *,
        proxies: ProxyRules | None = None,
        no_proxy: typing.Iterable[str] | None = None,
        trust_env: bool = False,
    ) -> None:
        self.proxies = self._build_proxies(proxies or {})
        self.no_proxy = [NoProxyRule.parse(token) for token in (no_proxy or [])]
        self.trust_env = trust_env
        self._environment = self._load_environment() if trust_env else {}

    @staticmethod
    def _build_proxies(proxies: ProxyRules) -> dict[str, Proxy | None]:
        from ._utils import URLPattern

        built: dict[str, Proxy | None] = {}
        seen: set[URLPattern] = set()
        for pattern, value in proxies.items():
            key = URLPattern(pattern)
            if key in seen:
                raise ValueError(f"Duplicate proxy route for {pattern!r}")
            seen.add(key)
            built[pattern] = None if value is None else Proxy(value)
        return dict(
            sorted(
                built.items(), key=lambda item: URLPattern(item[0]), reverse=True
            )
        )

    @classmethod
    def _load_environment(cls) -> dict[str, typing.Any]:
        proxy_info: dict[str, str] = {}
        for env_name, value in os.environ.items():
            lowered = env_name.lower()
            if lowered.endswith("_proxy"):
                key = lowered[:-6]
                if key not in ("http", "https", "all"):
                    continue
            elif lowered == "no_proxy":
                key = "no"
            else:
                continue
            if not value:
                continue
            current = proxy_info.get(key)
            if current is not None and current != value and sys.platform not in (
                "darwin",
                "win32",
            ):
                upper_name = "NO_PROXY" if key == "no" else f"{key.upper()}_PROXY"
                raise ValueError(
                    f"Conflicting proxy configuration in {upper_name!r} and "
                    f"{upper_name.lower()!r}"
                )
            proxy_info[key] = value
        proxies: dict[str, Proxy] = {}
        for scheme in ("http", "https", "all"):
            value = proxy_info.get(scheme)
            if value is None:
                continue
            if "://" not in value:
                value = f"http://{value}"
            proxies[scheme] = Proxy(value)

        no_proxy = proxy_info.get("no")
        rules = (
            [NoProxyRule.parse(token) for token in no_proxy.split(",") if token.strip()]
            if no_proxy
            else []
        )
        return {"proxies": proxies, "no_proxy": rules}

    @staticmethod
    def _pattern_match(
        patterns: typing.Mapping[str, typing.Any], url: URL
    ) -> tuple[str, typing.Any] | None:
        from ._utils import URLPattern

        for pattern, value in patterns.items():
            if URLPattern(pattern).matches(url):
                return pattern, value
        return None

    def environment_proxy_for(self, url: URL) -> tuple[str, Proxy] | None:
        proxies = self._environment.get("proxies", {})
        for scheme in (url.scheme, "all"):
            proxy = proxies.get(scheme)
            if proxy is not None:
                return f"{scheme}://", proxy
        return None

    @property
    def configured_proxies(self) -> list[Proxy]:
        proxies = list(self.proxies.values())
        proxies.extend(self._environment.get("proxies", {}).values())
        return list(dict.fromkeys(proxies))

    def route(
        self,
        url: URL,
        *,
        override: ProxyRule | UseClientDefaultType = USE_CLIENT_DEFAULT,
    ) -> ProxyDecision:
        if not url.scheme or not url.host:
            raise ValueError("Cannot route a relative URL")

        for rule in self._environment.get("no_proxy", []):
            if rule.matches(url):
                return ProxyDecision.direct_connection(
                    "NO_PROXY environment token bypassed proxy",
                    rule=rule.token,
                    source="environment",
                )
        for rule in self.no_proxy:
            if rule.matches(url):
                return ProxyDecision.direct_connection(
                    "NO_PROXY policy token bypassed proxy",
                    rule=rule.token,
                    source="policy",
                )

        if override is False or override is None:
            return ProxyDecision.direct_connection(
                "Per-request proxy override disabled the proxy", source="request"
            )
        if override is not USE_CLIENT_DEFAULT and override is not None:
            proxy = Proxy(override) if isinstance(override, (str, URL)) else override
            return ProxyDecision.via_proxy(
                proxy,
                "Per-request proxy override selected proxy",
                rule="request",
                source="request",
                url=url,
            )

        match = self._pattern_match(self.proxies, url)
        if match is not None:
            pattern, proxy = match
            if proxy is None:
                return ProxyDecision.direct_connection(
                    "Client proxy mapping explicitly bypassed proxy",
                    rule=pattern,
                    source="client",
                )
            return ProxyDecision.via_proxy(
                proxy,
                "Client proxy mapping selected proxy",
                rule=pattern,
                source="client",
                url=url,
            )

        environment_proxy = self.environment_proxy_for(url)
        if environment_proxy is not None:
            pattern, proxy = environment_proxy
            return ProxyDecision.via_proxy(
                proxy,
                "Environment proxy selected proxy",
                rule=pattern,
                source="environment",
                url=url,
            )

        return ProxyDecision.direct_connection("No proxy configured", source="default")
