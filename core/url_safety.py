"""
LANPool URL Safety & SSRF Validator (core/url_safety.py)
Validates download targets and redirect targets to prevent SSRF and internal network scanning.
Enforces scheme checks, rejects userinfo, resolves hostnames to IPs, and rejects
unspecified, multicast, broadcast, link-local, and loopback (unless explicitly allowed).
"""

import asyncio
import ipaddress
import urllib.parse


async def validate_download_url(url: str, allow_loopback: bool = True) -> str:
    """
    Asynchronously validates a download URL for safety against SSRF.
    Raises ValueError with a descriptive message if the URL violates safety policies.
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL must be a non-empty string.")

    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Invalid URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted.")

    if not parsed.netloc:
        raise ValueError("URL must contain a host.")

    if parsed.username or parsed.password:
        raise ValueError("URLs containing userinfo (username/password) are forbidden.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must contain a valid hostname or IP address.")

    loop = asyncio.get_running_loop()

    # Check if host is an IP literal
    try:
        ip_obj = ipaddress.ip_address(hostname)
        ips = [ip_obj]
    except ValueError:
        # Hostname: resolve via getaddrinfo
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        import socket
        try:
            addr_info = await loop.getaddrinfo(
                hostname,
                port,
                family=0,
                type=socket.SOCK_STREAM,
            )
        except Exception as e:
            raise ValueError(f"Failed to resolve host '{hostname}': {e}")

        if not addr_info:
            raise ValueError(f"Could not resolve any IP address for host '{hostname}'.")

        ips = []
        for item in addr_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            try:
                ips.append(ipaddress.ip_address(ip_str))
            except ValueError:
                pass

    if not ips:
        raise ValueError(f"No valid IP addresses resolved for '{hostname}'.")

    for ip in ips:
        if ip.is_unspecified:
            raise ValueError(f"Forbidden destination: '{hostname}' resolves to unspecified address ({ip}).")
        if ip.is_multicast:
            raise ValueError(f"Forbidden destination: '{hostname}' resolves to multicast address ({ip}).")
        if ip.is_link_local:
            raise ValueError(f"Forbidden destination: '{hostname}' resolves to link-local address ({ip}).")
        if str(ip) == "255.255.255.255":
            raise ValueError(f"Forbidden destination: '{hostname}' resolves to broadcast address ({ip}).")
        if ip.is_loopback and not allow_loopback:
            raise ValueError(f"Forbidden destination: '{hostname}' resolves to loopback address ({ip}) and loopback is disabled.")

    return url
