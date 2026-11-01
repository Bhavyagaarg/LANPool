"""Origin URL policy and a transport that connects to the IP it validated."""
import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit
import httpx
from config import ALLOW_LOOPBACK_DOWNLOADS, ALLOW_PRIVATE_DOWNLOADS, REQUEST_TIMEOUT_SECONDS


async def resolve_download_url(url, allow_loopback=False, allow_private=None):
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL must be a non-empty string")
    parsed = urlsplit(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Only absolute HTTP(S) URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are forbidden")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid destination port")
    allow_private = ALLOW_PRIVATE_DOWNLOADS if allow_private is None else allow_private
    try:
        addresses = [ipaddress.ip_address(parsed.hostname)]
    except ValueError:
        try:
            rows = await asyncio.get_running_loop().getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
            addresses = list({ipaddress.ip_address(row[4][0]) for row in rows})
        except OSError as exc:
            raise ValueError("Could not resolve destination") from exc
    if not addresses:
        raise ValueError("No destination addresses")
    for address in addresses:
        address = getattr(address, "ipv4_mapped", None) or address
        if address.is_unspecified or address.is_multicast or address.is_link_local or (address.is_reserved and not address.is_loopback) or str(address) == "255.255.255.255":
            raise ValueError("Forbidden destination address")
        if address.is_loopback:
            if not allow_loopback:
                raise ValueError("Loopback origin is disabled")
        elif not address.is_global and not allow_private:
            raise ValueError("Private/internal origin is disabled")
    return str(addresses[0])


async def validate_download_url(url, allow_loopback=False, allow_private=None):
    await resolve_download_url(url, allow_loopback, allow_private)
    return url.strip()


class PinnedOriginTransport(httpx.AsyncBaseTransport):
    """No proxy or second DNS lookup; retain Host and TLS certificate hostname."""
    def __init__(self):
        self.transports = {}

    async def handle_async_request(self, request):
        address = await resolve_download_url(str(request.url), ALLOW_LOOPBACK_DOWNLOADS)
        headers = request.headers.copy()
        headers["Host"] = request.url.netloc.decode("ascii")
        pinned = httpx.Request(request.method, request.url.copy_with(host=address), headers=headers, stream=request.stream, extensions={**request.extensions, "sni_hostname": request.url.host})
        key = (request.url.scheme, request.url.host, request.url.port)
        if key not in self.transports:
            self.transports[key] = httpx.AsyncHTTPTransport(trust_env=False)
        return await self.transports[key].handle_async_request(pinned)

    async def aclose(self):
        await asyncio.gather(*(transport.aclose() for transport in self.transports.values()))


def origin_client(timeout=REQUEST_TIMEOUT_SECONDS):
    return httpx.AsyncClient(transport=PinnedOriginTransport(), timeout=timeout, trust_env=False, follow_redirects=False)
