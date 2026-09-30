import pytest

from httpx._public_suffix import registrable_domain


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("example.com", "example.com"),
        ("www.example.com", "example.com"),
        ("example.co.uk", "example.co.uk"),
        ("shop.example.co.uk", "example.co.uk"),
        ("project.github.io", "project.github.io"),
        ("preview.project.github.io", "project.github.io"),
        ("example.amplifyapp.com", "example.amplifyapp.com"),
        ("preview.example.amplifyapp.com", "example.amplifyapp.com"),
    ],
)
def test_registrable_domain(host: str, expected: str) -> None:
    assert registrable_domain(host) == expected
