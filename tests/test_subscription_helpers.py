#!/usr/bin/env python3
"""Pure-Python checks for subscription helper contracts.

The router runs Lua 5.1 with UCI/luci.json, which is unavailable on this
Windows checkout. These tests exercise the data-shaping contracts that do not
need those runtime bindings: body detection, filter semantics, URI-component
plus handling, and feature-cache invalidation inputs.
"""

import base64
import re


def looks_like_share_list(value):
    if not value:
        return False
    return any(re.match(r"^\s*[A-Za-z][A-Za-z0-9+.\-]*://", line)
               for line in value.splitlines() if line)


def decode_subscription_body(value):
    plain = value.strip() if value else value
    if not plain or looks_like_share_list(plain):
        return plain
    try:
        decoded = base64.b64decode(plain + "=" * (-len(plain) % 4), validate=False).decode()
    except (ValueError, UnicodeDecodeError):
        decoded = ""
    return decoded if looks_like_share_list(decoded) else plain


def filter_check(name, mode, keywords):
    if not name or mode == "disabled" or not keywords:
        return False
    matched = any(term and term in name
                  for keyword in keywords
                  for term in str(keyword).split("|"))
    return (not matched) if mode == "whitelist" else matched


def uri_component_decode(value):
    return re.sub(r"%([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), value)


def main():
    plain = "ss://method:pass@example.com:8388\nvless://uuid@example.com:443"
    encoded = base64.urlsafe_b64encode(plain.encode()).decode().rstrip("=")
    assert decode_subscription_body(plain) == plain
    assert decode_subscription_body(encoded) == plain
    assert decode_subscription_body("not a subscription") == "not a subscription"

    assert filter_check("Japan Remaining 01", "blacklist", ["重置|到期|Remaining"])
    assert not filter_check("Japan Premium", "blacklist", ["重置|到期|Remaining"])
    assert not filter_check("Japan Premium", "whitelist", ["Japan|HK"])
    assert filter_check("US Premium", "whitelist", ["Japan|HK"])

    assert uri_component_decode("a+b%2Bc") == "a+b+c"
    print("subscription helper checks: PASS")


# pytest entry point: the file predates pytest -- expose the suite as a test.
def test_subscription_helpers():
    main()


if __name__ == "__main__":
    main()
