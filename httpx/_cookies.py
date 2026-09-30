from __future__ import annotations

import ipaddress
import threading
import typing
from http.cookiejar import Cookie, CookieJar, DefaultCookiePolicy

SameSitePolicy = str

RFC6265 = "rfc6265"
LAX = "lax"
STRICT = "strict"
NONE = "none"

# This is a deliberately small built-in fallback rather than a dependency on
# the complete Public Suffix List. The values cover common multi-label
# suffixes used by web sites; custom suffixes can be supplied to Cookies.
PUBLIC_SUFFIXES = frozenset(
    {
        "ac.ae",
        "ac.at",
        "ac.be",
        "ac.cn",
        "ac.il",
        "ac.in",
        "ac.jp",
        "ac.kr",
        "ac.nz",
        "ac.ru",
        "ac.th",
        "ac.uk",
        "ac.za",
        "asn.au",
        "co.at",
        "co.cz",
        "co.hu",
        "co.id",
        "co.il",
        "co.in",
        "co.jp",
        "co.kr",
        "co.nz",
        "co.ru",
        "co.th",
        "co.uk",
        "co.za",
        "com.au",
        "com.br",
        "com.cn",
        "com.hk",
        "com.mx",
        "com.ru",
        "com.sg",
        "com.tr",
        "com.tw",
        "edu.au",
        "edu.cn",
        "edu.hk",
        "edu.mx",
        "edu.ru",
        "edu.sg",
        "edu.tr",
        "edu.tw",
        "edu.uk",
        "go.id",
        "go.jp",
        "go.kr",
        "go.th",
        "gov.au",
        "gov.cn",
        "gov.hk",
        "gov.ru",
        "gov.sg",
        "gov.tr",
        "gov.tw",
        "gov.uk",
        "govt.nz",
        "github.io",
        "id.au",
        "iinet.net.au",
        "is-a.dev",
        "mil.ru",
        "mod.uk",
        "ne.jp",
        "net.au",
        "net.cn",
        "net.hk",
        "net.nz",
        "net.ru",
        "net.sg",
        "net.th",
        "net.tw",
        "net.uk",
        "nhs.uk",
        "nic.in",
        "or.at",
        "or.id",
        "or.jp",
        "or.kr",
        "or.ru",
        "or.th",
        "org.au",
        "org.br",
        "org.cn",
        "org.hk",
        "org.in",
        "org.nz",
        "org.ru",
        "org.sg",
        "org.tr",
        "org.tw",
        "org.uk",
        "org.za",
        "parliament.nz",
        "police.uk",
        "web.id",
    }
)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def public_suffix(host: str, suffixes: typing.Container[str] = PUBLIC_SUFFIXES) -> str:
    labels = host.strip("[]").rstrip(".").lower().split(".")
    for length in range(len(labels), 0, -1):
        candidate = ".".join(labels[-length:])
        if candidate in suffixes:
            return candidate
        wildcard = "*." + ".".join(labels[-length + 1 :])
        if wildcard in suffixes:
            return candidate
    return labels[-1] if labels else ""


def registrable_domain(
    host: str, suffixes: typing.Container[str] = PUBLIC_SUFFIXES
) -> str:
    bracketed = host.startswith("[") and host.endswith("]")
    normalized = host.strip("[]").rstrip(".").lower()
    if is_ip_literal(normalized):
        return f"[{normalized}]" if bracketed else normalized
    suffix = public_suffix(normalized, suffixes)
    labels = normalized.split(".")
    suffix_labels = suffix.split(".") if suffix else []
    if len(labels) <= len(suffix_labels):
        return normalized
    return ".".join(labels[-len(suffix_labels) - 1 :])


def same_site(
    current_scheme: str,
    current_host: str,
    initiator_scheme: str | None,
    initiator_host: str | None,
    suffixes: typing.Container[str] = PUBLIC_SUFFIXES,
) -> bool:
    if initiator_scheme is None or initiator_host is None:
        return True
    current = current_host.strip("[]").lower()
    initiator = initiator_host.strip("[]").lower()
    if is_ip_literal(current) or is_ip_literal(initiator):
        return (
            current_scheme.lower() == initiator_scheme.lower()
            and current == initiator
        )
    return (
        current_scheme.lower() == initiator_scheme.lower()
        and registrable_domain(current, suffixes)
        == registrable_domain(initiator, suffixes)
    )


class SameSiteCookiePolicy(DefaultCookiePolicy):
    def __init__(
        self,
        policy: SameSitePolicy = RFC6265,
        public_suffixes: typing.Container[str] = PUBLIC_SUFFIXES,
        **kwargs: typing.Any,
    ) -> None:
        super().__init__(**kwargs)
        normalized = policy.lower()
        if normalized not in {RFC6265, LAX, STRICT, NONE}:
            raise ValueError(f"Unsupported SameSite cookie policy: {policy!r}")
        self.same_site_policy = normalized
        self.public_suffixes = public_suffixes

    def set_ok_domain(self, cookie: Cookie, request: typing.Any) -> bool:
        if not super().set_ok_domain(cookie, request):
            return False
        if self.same_site_policy == RFC6265:
            return True
        if not cookie.domain_specified:
            return True

        host = request.request.url.raw_host.decode("ascii").strip("[]").lower()
        domain = cookie.domain.lstrip(".").lower()
        if is_ip_literal(host):
            return False
        suffix = public_suffix(host, self.public_suffixes)
        if domain == suffix:
            return False
        site = registrable_domain(host, self.public_suffixes)
        if domain == site:
            return True
        if not host.endswith("." + domain):
            return False
        return True

    def set_ok(self, cookie: Cookie, request: typing.Any) -> bool:
        if not super().set_ok(cookie, request):
            return False
        if (
            self.same_site_policy != RFC6265
            and self._cookie_same_site(cookie) == NONE
        ):
            if not cookie.secure or request.type not in self.secure_protocols:
                return False
        return True

    def _request_port(self, request: typing.Any) -> int:
        request_port = request.request.url.port
        if request_port is None:
            return 443 if request.request.url.scheme == "https" else 80
        return request_port

    def _cookie_ports(self, cookie: Cookie) -> set[str]:
        return {
            port.strip().strip('"')
            for port in (cookie.port or "").split(",")
            if port.strip()
        }

    def set_ok_port(self, cookie: Cookie, request: typing.Any) -> bool:
        if not cookie.port_specified:
            return True
        return str(self._request_port(request)) in self._cookie_ports(cookie)

    def return_ok_port(self, cookie: Cookie, request: typing.Any) -> bool:
        if not cookie.port:
            return True
        return str(self._request_port(request)) in self._cookie_ports(cookie)

    def path_return_ok(self, path: str, request: typing.Any) -> bool:
        request_path = request.request.url.raw_path.decode("ascii").split("?", 1)[0]
        return request_path == path or (
            request_path.startswith(path)
            and (path.endswith("/") or request_path[len(path) : len(path) + 1] == "/")
        )

    def domain_return_ok(self, domain: str, request: typing.Any) -> bool:
        host = request.request.url.raw_host.decode("ascii").strip("[]").lower()
        if is_ip_literal(host):
            return bool(domain) and domain.lstrip(".").lower() == host
        jar = getattr(self, "_httpx_jar", None)
        paths = jar._cookies.get(domain, {}) if jar is not None else {}
        cookies_for_domain = [
            cookie
            for path_cookies in paths.values()
            for cookie in path_cookies.values()
        ]
        if cookies_for_domain and all(
            not cookie.domain_specified
            and not cookie.get_nonstandard_attr("_HTTPX_GLOBAL", False)
            for cookie in cookies_for_domain
        ):
            return domain.lstrip(".").lower() == host
        return super().domain_return_ok(domain, request)

    def return_ok_domain(self, cookie: Cookie, request: typing.Any) -> bool:
        request_host = (
            request.request.url.raw_host.decode("ascii").strip("[]").lower()
        )
        if is_ip_literal(request_host):
            if not cookie.domain_specified and not cookie.domain:
                return False
            stored_host = cookie.domain or request_host
            return stored_host.lstrip(".").lower() == request_host
        return super().return_ok_domain(cookie, request)

    def return_ok(self, cookie: Cookie, request: typing.Any) -> bool:
        if not super().return_ok(cookie, request):
            return False
        if self.same_site_policy == RFC6265:
            return True

        attribute = self._cookie_same_site(cookie)
        if attribute == NONE and request.type not in self.secure_protocols:
            return False
        if attribute == NONE:
            return True
        if attribute == STRICT and not request.httpx_same_site:
            return False
        if attribute == LAX and not self._lax_allowed(cookie, request):
            return False
        return True

    def _cookie_same_site(self, cookie: Cookie) -> str:
        for key, value in cookie._rest.items():
            if key.lower() != "samesite":
                continue
            normalized = str(value or "").strip().lower()
            if normalized in {LAX, STRICT, NONE}:
                return normalized
            return LAX
        return LAX if self.same_site_policy != RFC6265 else ""

    def _lax_allowed(self, cookie: Cookie, request: typing.Any) -> bool:
        if request.httpx_same_site:
            return True
        if request.request.method not in {"GET", "HEAD", "OPTIONS", "TRACE"}:
            return False
        return bool(request.httpx_top_level)


class PolicyCookieJar(CookieJar):
    def __init__(
        self,
        policy: SameSitePolicy = RFC6265,
        public_suffixes: typing.Container[str] = PUBLIC_SUFFIXES,
    ) -> None:
        super().__init__(
            SameSiteCookiePolicy(policy=policy, public_suffixes=public_suffixes)
        )
        self._policy._httpx_jar = self
        self._policy_lock = threading.RLock()

    def __iter__(self) -> typing.Iterator[Cookie]:  # type: ignore[override]
        with self._cookies_lock:
            cookies = [
                cookie
                for domains in self._cookies.values()
                for paths in domains.values()
                for cookie in paths.values()
            ]
        return iter(cookies)

    def __len__(self) -> int:
        with self._cookies_lock:
            return sum(
                len(paths)
                for domains in self._cookies.values()
                for paths in domains.values()
            )

    def add_cookie_header(  # type: ignore[override]
        self, request: typing.Any
    ) -> None:
        with self._policy_lock:
            super().add_cookie_header(request)
            self.clear_expired_cookies()

    def extract_cookies(  # type: ignore[override]
        self, response: typing.Any, request: typing.Any | None = None
    ) -> None:
        with self._policy_lock:
            super().extract_cookies(response, request)
            self.clear_expired_cookies()
