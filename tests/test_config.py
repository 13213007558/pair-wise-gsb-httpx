import ssl
import typing
from pathlib import Path

import certifi
import pytest

import httpx


def test_load_ssl_config():
    context = httpx.create_ssl_context()
    assert context.verify_mode == ssl.VerifyMode.CERT_REQUIRED
    assert context.check_hostname is True


def test_load_ssl_config_verify_non_existing_file():
    with pytest.raises(IOError):
        context = httpx.create_ssl_context()
        context.load_verify_locations(cafile="/path/to/nowhere")


def test_load_ssl_with_keylog(monkeypatch: typing.Any) -> None:
    monkeypatch.setenv("SSLKEYLOGFILE", "test")
    context = httpx.create_ssl_context()
    assert context.keylog_filename == "test"


def test_load_ssl_config_verify_existing_file():
    context = httpx.create_ssl_context()
    context.load_verify_locations(capath=certifi.where())
    assert context.verify_mode == ssl.VerifyMode.CERT_REQUIRED
    assert context.check_hostname is True


def test_load_ssl_config_verify_directory():
    context = httpx.create_ssl_context()
    context.load_verify_locations(capath=Path(certifi.where()).parent)
    assert context.verify_mode == ssl.VerifyMode.CERT_REQUIRED
    assert context.check_hostname is True


def test_load_ssl_config_cert_and_key(cert_pem_file, cert_private_key_file):
    context = httpx.create_ssl_context()
    context.load_cert_chain(cert_pem_file, cert_private_key_file)
    assert context.verify_mode == ssl.VerifyMode.CERT_REQUIRED
    assert context.check_hostname is True


@pytest.mark.parametrize("password", [b"password", "password"])
def test_load_ssl_config_cert_and_encrypted_key(
    cert_pem_file, cert_encrypted_private_key_file, password
):
    context = httpx.create_ssl_context()
    context.load_cert_chain(cert_pem_file, cert_encrypted_private_key_file, password)
    assert context.verify_mode == ssl.VerifyMode.CERT_REQUIRED
    assert context.check_hostname is True


def test_load_ssl_config_cert_and_key_invalid_password(
    cert_pem_file, cert_encrypted_private_key_file
):
    with pytest.raises(ssl.SSLError):
        context = httpx.create_ssl_context()
        context.load_cert_chain(
            cert_pem_file, cert_encrypted_private_key_file, "password1"
        )


def test_load_ssl_config_cert_without_key_raises(cert_pem_file):
    with pytest.raises(ssl.SSLError):
        context = httpx.create_ssl_context()
        context.load_cert_chain(cert_pem_file)


def test_load_ssl_config_no_verify():
    context = httpx.create_ssl_context(verify=False)
    assert context.verify_mode == ssl.VerifyMode.CERT_NONE
    assert context.check_hostname is False


def test_SSLContext_with_get_request(server, cert_pem_file):
    context = httpx.create_ssl_context()
    context.load_verify_locations(cert_pem_file)
    response = httpx.get(server.url, verify=context)
    assert response.status_code == 200


def test_limits_repr():
    limits = httpx.Limits(max_connections=100)
    expected = (
        "Limits(max_connections=100, max_keepalive_connections=None,"
        " keepalive_expiry=5.0)"
    )
    assert repr(limits) == expected


def test_limits_eq():
    limits = httpx.Limits(max_connections=100)
    assert limits == httpx.Limits(max_connections=100)


def test_timeout_eq():
    timeout = httpx.Timeout(timeout=5.0)
    assert timeout == httpx.Timeout(timeout=5.0)


def test_timeout_all_parameters_set():
    timeout = httpx.Timeout(
        total=5.0, dns=5.0, connect=5.0, read=5.0, write=5.0, pool=5.0
    )
    assert timeout == httpx.Timeout(total=5.0)


def test_simple_timeout_has_no_total_budget():
    timeout = httpx.Timeout(timeout=5.0)
    assert timeout.total is None
    assert timeout.dns == 5.0
    assert timeout.connect == 5.0
    assert timeout.read == 5.0
    assert timeout.write == 5.0
    assert timeout.pool == 5.0


def test_timeout_from_nothing():
    timeout = httpx.Timeout(None)
    assert timeout.total is None
    assert timeout.dns is None
    assert timeout.connect is None
    assert timeout.read is None
    assert timeout.write is None
    assert timeout.pool is None


def test_timeout_from_none():
    timeout = httpx.Timeout(timeout=None)
    assert timeout == httpx.Timeout(None)


def test_timeout_from_one_none_value():
    timeout = httpx.Timeout(None, read=None)
    assert timeout == httpx.Timeout(None)


def test_timeout_from_one_value():
    timeout = httpx.Timeout(None, read=5.0)
    assert timeout.dns is None
    assert timeout.connect is None
    assert timeout.read == 5.0
    assert timeout.write is None
    assert timeout.pool is None


def test_timeout_from_one_value_and_default():
    timeout = httpx.Timeout(5.0, pool=60.0)
    assert timeout == httpx.Timeout(timeout=(5.0, 5.0, 5.0, 60.0))


def test_timeout_missing_default():
    with pytest.raises(ValueError):
        httpx.Timeout(pool=60.0)


def test_timeout_from_tuple():
    timeout = httpx.Timeout(timeout=(5.0, 5.0, 5.0, 5.0))
    assert timeout == httpx.Timeout(timeout=5.0)


def test_total_timeout_sets_each_operation():
    timeout = httpx.Timeout(total=30.0, dns=2.0)
    assert timeout.total == 30.0
    assert timeout.dns == 2.0
    assert timeout.connect == 30.0
    assert timeout.read == 30.0
    assert timeout.write == 30.0
    assert timeout.pool == 30.0


def test_client_requested_budget_configuration():
    timeout = httpx.Timeout(
        total=30.0,
        dns=2.0,
        connect=5.0,
        read=10.0,
        write=None,
        pool=5.0,
    )

    assert timeout.as_dict() == {
        "total": 30.0,
        "dns": 2.0,
        "connect": 5.0,
        "read": 10.0,
        "write": None,
        "pool": 5.0,
    }


def test_explicit_none_and_zero_remain_distinct():
    timeout = httpx.Timeout(total=30.0, write=None, read=0.0)
    assert timeout.write is None
    assert timeout.read == 0.0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"total": 30.0, "connect": 31.0},
        {"total": 30.0, "read": 31.0},
        {"total": 30.0, "write": 31.0},
        {"total": 30.0, "pool": 31.0},
        {"total": 30.0, "connect": 5.0, "dns": 6.0},
    ],
)
def test_timeout_rejects_contradictory_budgets(kwargs):
    with pytest.raises(ValueError):
        httpx.Timeout(**kwargs)


@pytest.mark.parametrize("kwargs", [{"total": -1.0}, {"total": float("inf")}])
def test_timeout_rejects_invalid_budget(kwargs):
    with pytest.raises(ValueError):
        httpx.Timeout(**kwargs)


def test_timeout_rejects_non_numeric_budget():
    with pytest.raises(TypeError):
        httpx.Timeout(total="30")  # type: ignore[arg-type]


def test_timeout_from_config_instance():
    timeout = httpx.Timeout(timeout=5.0)
    assert httpx.Timeout(timeout) == httpx.Timeout(timeout=5.0)


def test_timeout_repr():
    timeout = httpx.Timeout(timeout=5.0)
    assert repr(timeout) == "Timeout(timeout=5.0)"

    timeout = httpx.Timeout(None, read=5.0)
    assert repr(timeout) == (
        "Timeout(total=None, dns=None, connect=None, read=5.0, "
        "write=None, pool=None)"
    )


def test_proxy_from_url():
    proxy = httpx.Proxy("https://example.com")

    assert str(proxy.url) == "https://example.com"
    assert proxy.auth is None
    assert proxy.headers == {}
    assert repr(proxy) == "Proxy('https://example.com')"


def test_proxy_with_auth_from_url():
    proxy = httpx.Proxy("https://username:password@example.com")

    assert str(proxy.url) == "https://example.com"
    assert proxy.auth == ("username", "password")
    assert proxy.headers == {}
    assert repr(proxy) == "Proxy('https://example.com', auth=('username', '********'))"


def test_invalid_proxy_scheme():
    with pytest.raises(ValueError):
        httpx.Proxy("invalid://example.com")
