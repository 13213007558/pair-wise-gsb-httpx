from __future__ import annotations

import idna

# Compact multi-label Public Suffix List rules. Single-label suffixes fall
# back to the final DNS label.
PUBLIC_SUFFIXES = frozenset(
    [
        "*.bd",
        "*.ck",
        "*.er",
        "*.fk",
        "*.jm",
        "*.kh",
        "*.mm",
        "*.nom.br",
        "*.np",
        "*.pg",
        "*.sch.uk",
        "!www.ck",
        "ac.cn",
        "ac.id",
        "ac.jp",
        "ac.kr",
        "ac.uk",
        "ac.nz",
        "app.render.com",
        "appspot.com",
        "*.amplifyapp.com",
        "azurewebsites.net",
        "blogspot.com",
        "cloudapp.azure.com",
        "co.in",
        "co.jp",
        "co.kr",
        "co.nz",
        "co.uk",
        "co.za",
        "com.de",
        "com.ec",
        "com.eg",
        "com.au",
        "com.br",
        "com.cn",
        "com.hk",
        "com.mx",
        "com.my",
        "com.sg",
        "com.tr",
        "com.tw",
        "com.ua",
        "edu.au",
        "edu.cn",
        "edu.tw",
        "firm.in",
        "firebaseapp.com",
        "fly.dev",
        "gen.in",
        "github.io",
        "gitlab.io",
        "go.jp",
        "gov.au",
        "gov.br",
        "gov.cn",
        "gov.in",
        "gov.uk",
        "govt.nz",
        "herokuapp.com",
        "ind.in",
        "ltd.uk",
        "me.uk",
        "myshopify.com",
        "ne.jp",
        "ne.kr",
        "net.au",
        "net.br",
        "net.cn",
        "net.nz",
        "net.uk",
        "netlify.app",
        "nhs.uk",
        "onrender.com",
        "or.jp",
        "or.kr",
        "org.au",
        "org.br",
        "org.cn",
        "org.in",
        "org.nz",
        "org.tw",
        "org.uk",
        "org.za",
        "pages.dev",
        "plc.uk",
        "police.uk",
        "pythonanywhere.com",
        "railway.app",
        "s3.dualstack.us-east-1.amazonaws.com",
        "s3.dualstack.us-west-2.amazonaws.com",
        "s3.us-east-1.amazonaws.com",
        "s3.us-west-2.amazonaws.com",
        "vercel.app",
        "web.app",
        "workers.dev",
    ]
)


def _encode_host(host: str) -> list[str]:
    try:
        encoded = idna.encode(host).decode("ascii")
    except (UnicodeError, ValueError):
        encoded = host
    return [label for label in encoded.lower().rstrip(".").split(".") if label]


def public_suffix(host: str, suffixes: frozenset[str] = PUBLIC_SUFFIXES) -> str:
    labels = _encode_host(host)
    if not labels:
        return ""

    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if f"!{candidate}" in suffixes:
            return ".".join(labels[index + 1 :])

    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in suffixes:
            return candidate
        if index > 0 and f"*.{candidate}" in suffixes:
            return ".".join(labels[index - 1 :])

    return labels[-1]


def registrable_domain(host: str) -> str:
    labels = _encode_host(host)
    suffix = public_suffix(host)
    suffix_labels = suffix.split(".") if suffix else []
    wildcard = (
        f"*.{'.'.join(suffix_labels[1:])}" if len(suffix_labels) > 1 else None
    )
    if wildcard is not None and wildcard in PUBLIC_SUFFIXES:
        suffix_labels = suffix_labels[1:]
    if len(labels) <= len(suffix_labels):
        return ".".join(labels)
    return ".".join(labels[-(len(suffix_labels) + 1) :])
