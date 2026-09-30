from __future__ import annotations

import ipaddress
import re
import typing
from dataclasses import dataclass, replace
from urllib.request import getproxies

from ._config import Proxy
from ._urls import URL
from ._utils import URLPattern

if typing.TYPE_CHECKING:  # pragma: no cover
    from ._types import ProxyTypes


__all__ = ["ProxyRoute", "ProxyRoutingPolicy"]

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}
VALID_SCHEMES = frozenset(DEFAULT_PORTS)


@dataclass(frozen=True)
class _NoProxyRule:
    token: str
    scheme: str
    port: int | None
    host: str | None = None
    network: ipaddress._BaseNetwork | None = None
    wildcard: bool = False


@dataclass(frozen=True)
class _ProxyMapRule:
    pattern: URLPattern
    proxy: Proxy | None
    source: str


@dataclass(frozen=True)
class ProxyRoute:
    status: str
    reason: str
    proxy: Proxy | None = None
    connect_line: str | None = None
    rejection_reason: str | None = None
    reasons: tuple[str, ...] = ()

    @property
    def is_direct(self) -> bool:
        return self.status == "direct"

    @property
    def is_proxy(self) -> bool:
        return self.status == "proxy"

    @property
    def is_rejected(self) -> bool:
        return self.status == "rejected"


def effective_port(url: URL) -> int | None:
    if url.port is not None:
        return url.port
    return DEFAULT_PORTS.get(url.scheme)


def normalized_host(url: URL) -> str:
    host = url.raw_host.decode("ascii").lower()
    if host.endswith(".") and not host.endswith(".."):
        host = host[:-1]
    return host


def bracketed_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def connect_line(target: URL, proxy: Proxy) -> str | None:
    if target.scheme != "https" or proxy.url.scheme not in ("http", "https"):
        return None
    host = normalized_host(target)
    port = effective_port(target)
    if not host or port is None:
        return None
    return f"CONNECT {bracketed_host(host)}:{port} HTTP/1.1"


def parse_port(value: str | None, token: str) -> int | None:
    if value is None:
        return None
    if not re.fullmatch(r"\d+", value):
        raise ValueError(f"Invalid NO_PROXY token {token!r}: port must be numeric.")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError(
            f"Invalid NO_PROXY token {token!r}: port must be between 1 and 65535."
        )
    return port


def valid_domain(host: str, token: str) -> None:
    if not host or host == "." or ".." in host:
        raise ValueError(f"Invalid NO_PROXY token {token!r}: invalid hostname.")
    if not re.fullmatch(r"[a-z0-9_.-]+", host):
        raise ValueError(f"Invalid NO_PROXY token {token!r}: invalid hostname.")
    labels = host.strip(".").split(".")
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        raise ValueError(f"Invalid NO_PROXY token {token!r}: invalid hostname.")


def parse_domain_token(token: str, scheme: str, port_text: str | None) -> _NoProxyRule:
    port = parse_port(port_text, token)
    if token == "*":
        return _NoProxyRule(token=token, scheme=scheme, port=port, wildcard=True)

    strict_subdomain = False
    host_text = token
    if host_text.startswith("*."):
        strict_subdomain = True
        host_text = host_text[2:]
    elif host_text.startswith("."):
        strict_subdomain = True
        host_text = host_text[1:]
    elif "*" in host_text:
        raise ValueError(
            f"Invalid NO_PROXY token {token!r}: wildcard is only supported as "
            "'*', '*.example.com', or '.example.com'."
        )

    try:
        host = normalized_host(URL(f"{scheme}://{host_text}"))
    except Exception:
        raise ValueError(f"Invalid NO_PROXY token {token!r}: invalid hostname.") from None
    if strict_subdomain:
        host = "." + host
    valid_domain(host, token)
    return _NoProxyRule(token=token, scheme=scheme, host=host, port=port)


def parse_network_token(token: str, scheme: str) -> _NoProxyRule:
    try:
        network = ipaddress.ip_network(token, strict=True)
    except ValueError as exc:
        raise ValueError(f"Invalid NO_PROXY token {token!r}: {exc}.") from None
    return _NoProxyRule(token=token, scheme=scheme, port=None, network=network)


def parse_no_proxy_token(token: str) -> _NoProxyRule:
    if not token:
        raise ValueError("Invalid NO_PROXY token '': tokens must not be empty.")
    if any(char.isspace() for char in token):
        raise ValueError(f"Invalid NO_PROXY token {token!r}: whitespace is not allowed.")
    if any(char in token for char in "?#@"):
        raise ValueError(
            f"Invalid NO_PROXY token {token!r}: query, fragment, and userinfo "
            "components are not allowed."
        )

    scheme = "all"
    authority = token
    if "://" in token:
        scheme_text, _, authority = token.partition("://")
        scheme = scheme_text.lower()
        if scheme not in VALID_SCHEMES:
            raise ValueError(
                f"Invalid NO_PROXY token {token!r}: unsupported scheme {scheme_text!r}."
            )
        if "/" in authority:
            raise ValueError(
                f"Invalid NO_PROXY token {token!r}: path components are not allowed."
            )
    elif "/" in token:
        address_text, _, remainder = token.partition("/")
        prefix_text, separator, port_text = remainder.partition(":")
        if separator or not prefix_text:
            raise ValueError(
                f"Invalid NO_PROXY token {token!r}: ports cannot be combined "
                "with an IP network."
            )
        if address_text.startswith("["):
            raise ValueError(
                f"Invalid NO_PROXY token {token!r}: bracketed networks are not "
                "supported; use '2001:db8::/32'."
            )
        return parse_network_token(f"{address_text}/{prefix_text}", scheme)

    if authority.startswith("["):
        match = re.fullmatch(r"\[(?P<host>[^]]*)](?::(?P<port>\d+))?", authority)
        if match is None:
            raise ValueError(
                f"Invalid NO_PROXY token {token!r}: malformed IPv6 literal. "
                "Use '[::1]' or '[::1]:443'."
            )
        host_text = match.group("host")
        port = parse_port(match.group("port"), token)
        try:
            if "/" in host_text:
                if port is not None:
                    raise ValueError("ports cannot be combined with an IP network.")
                network = ipaddress.ip_network(host_text, strict=True)
                return _NoProxyRule(token=token, scheme=scheme, port=None, network=network)
            address = ipaddress.ip_address(host_text)
        except ValueError as exc:
            raise ValueError(f"Invalid NO_PROXY token {token!r}: {exc}.") from None
        return _NoProxyRule(token=token, scheme=scheme, host=str(address), port=port)

    if authority.count(":") > 1:
        try:
            address = ipaddress.ip_address(authority)
        except ValueError:
            raise ValueError(
                f"Invalid NO_PROXY token {token!r}: IPv6 literals with a port must "
                "be enclosed in square brackets."
            ) from None
        return _NoProxyRule(token=token, scheme=scheme, host=str(address), port=None)

    host_text, separator, port_text = authority.rpartition(":")
    if not separator:
        host_text, port_text = authority, None

    try:
        address = ipaddress.ip_address(host_text)
    except ValueError:
        return parse_domain_token(host_text, scheme, port_text)
    return _NoProxyRule(
        token=token, scheme=scheme, host=str(address), port=parse_port(port_text, token)
    )


def parse_no_proxy(
    value: str | typing.Sequence[str] | None,
) -> tuple[_NoProxyRule, ...]:
    if value is None:
        return ()
    tokens = value.split(",") if isinstance(value, str) else list(value)
    rules: list[_NoProxyRule] = []
    errors: list[str] = []
    for token in (item.strip() for item in tokens):
        try:
            rules.append(parse_no_proxy_token(token))
        except ValueError as exc:
            errors.append(str(exc))
    if errors:
        raise ValueError(" ".join(errors))
    return tuple(rules)


def coerce_proxy(proxy: ProxyTypes) -> Proxy:
    return Proxy(url=proxy) if isinstance(proxy, (str, URL)) else proxy


class ProxyRoutingPolicy:
    def __init__(
        self,
        proxies: typing.Mapping[str, ProxyTypes | None] | None = None,
        *,
        no_proxy: str | typing.Sequence[str] | None = None,
    ) -> None:
        rules: list[_ProxyMapRule] = []
        errors: list[str] = []
        for key, value in (proxies or {}).items():
            try:
                pattern = URLPattern(key)
                selected = None if value is None else coerce_proxy(value)
            except ValueError as exc:
                errors.append(str(exc))
            else:
                rules.append(_ProxyMapRule(pattern, selected, "client"))
        if errors:
            raise ValueError(" ".join(errors))
        self.proxy_rules = tuple(rules)
        self.no_proxy_rules = parse_no_proxy(no_proxy)

    @classmethod
    def from_environment(cls) -> ProxyRoutingPolicy:
        environment = getproxies()
        proxies: dict[str, str] = {}
        for scheme in ("http", "https", "all"):
            value = environment.get(scheme)
            if value:
                proxies[f"{scheme}://"] = (
                    value if "://" in value else f"http://{value}"
                )
        policy = cls(proxies, no_proxy=environment.get("no"))
        policy.proxy_rules = tuple(
            replace(rule, source="environment") for rule in policy.proxy_rules
        )
        return policy

    def merged(self, other: ProxyRoutingPolicy | None) -> ProxyRoutingPolicy:
        if other is None:
            return self
        merged = ProxyRoutingPolicy()
        merged.proxy_rules = self.proxy_rules + other.proxy_rules
        merged.no_proxy_rules = self.no_proxy_rules + other.no_proxy_rules
        return merged

    @property
    def has_proxy_routes(self) -> bool:
        return any(rule.proxy is not None for rule in self.proxy_rules)

    def no_proxy_route(self, url: URL) -> ProxyRoute | None:
        scheme = url.scheme
        host = normalized_host(url)
        port = effective_port(url)
        if not host or port is None:
            return None
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None

        for rule in self.no_proxy_rules:
            if rule.scheme not in ("all", scheme):
                continue
            if rule.port is not None and rule.port != port:
                continue
            if rule.wildcard:
                matched = True
            elif rule.network is not None:
                matched = (
                    address is not None
                    and address.version == rule.network.version
                    and address in rule.network
                )
            elif address is not None:
                matched = rule.host == str(address)
            elif rule.host is not None:
                if rule.host.startswith("."):
                    matched = host.endswith(rule.host)
                else:
                    matched = host == rule.host or host.endswith("." + rule.host)
            else:
                matched = False

            if matched:
                reason = (
                    f"NO_PROXY token {rule.token!r} matched {scheme}://"
                    f"{bracketed_host(host)}:{port}; connecting directly."
                )
                return ProxyRoute("direct", reason, reasons=(reason,))
        return None

    def route_for_url(
        self,
        url: URL | str,
        *,
        proxy: ProxyTypes | bool | None = None,
        redirected_from: URL | str | None = None,
    ) -> ProxyRoute:
        url = URL(url)
        prefix: tuple[str, ...] = ()
        if redirected_from is not None:
            prefix = (
                f"Redirect from {redirected_from} to {url}; proxy route was "
                "re-evaluated for the new target.",
            )

        no_proxy_route = self.no_proxy_route(url)
        if no_proxy_route is not None:
            if proxy not in (None, False):
                reason = (
                    "Per-request proxy override was rejected because NO_PROXY "
                    "always takes precedence."
                )
                return ProxyRoute(
                    "direct",
                    reason,
                    reasons=prefix + no_proxy_route.reasons + (reason,),
                )
            return ProxyRoute(
                no_proxy_route.status,
                no_proxy_route.reason,
                reasons=prefix + no_proxy_route.reasons,
            )

        if proxy is False:
            reason = "Per-request override selected a direct connection."
            return ProxyRoute("direct", reason, reasons=prefix + (reason,))
        if proxy is not None:
            try:
                selected_proxy = coerce_proxy(proxy)
            except (TypeError, ValueError) as exc:
                reason = f"Per-request proxy override was rejected: {exc}"
                return ProxyRoute(
                    "rejected",
                    reason,
                    rejection_reason=str(exc),
                    reasons=prefix + (reason,),
                )
            line = connect_line(url, selected_proxy)
            reason = f"Per-request override selected proxy {selected_proxy.url}."
            if line:
                reason += f" CONNECT request: {line}"
            return ProxyRoute(
                "proxy",
                reason,
                proxy=selected_proxy,
                connect_line=line,
                reasons=prefix + (reason,),
            )

        matches = [rule for rule in self.proxy_rules if rule.pattern.matches(url)]
        if not matches:
            reason = "No proxy rule matched; connecting directly."
            return ProxyRoute("direct", reason, reasons=prefix + (reason,))

        matches.sort(key=lambda rule: rule.pattern.priority)
        explicit = next(
            (rule for rule in matches if rule.source == "client" and rule.proxy is not None),
            None,
        )
        direct = next((rule for rule in matches if rule.proxy is None), None)
        selected_rule = explicit or direct or matches[0]

        if selected_rule.proxy is None:
            reason = (
                f"Proxy map key {selected_rule.pattern.pattern!r} explicitly selected "
                "a direct connection."
            )
            return ProxyRoute("direct", reason, reasons=prefix + (reason,))

        line = connect_line(url, selected_rule.proxy)
        reason = (
            f"{selected_rule.source.title()} proxy rule "
            f"{selected_rule.pattern.pattern!r} selected proxy "
            f"{selected_rule.proxy.url}."
        )
        if line:
            reason += f" CONNECT request: {line}"
        return ProxyRoute(
            "proxy",
            reason,
            proxy=selected_rule.proxy,
            connect_line=line,
            reasons=prefix + (reason,),
        )
