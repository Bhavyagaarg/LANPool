"""Signed peer messages use a separate key; the admin token never leaves a node.

HMAC provides integrity, not confidentiality. Use a trusted LAN/VPN or TLS proxy.
"""
import hashlib
import hmac
import json
import time
import uuid
import os
import ssl
import re
from config import PEER_SECRET


def mac(value, secret=PEER_SECRET):
    return hmac.new(secret.encode(), value.encode(), hashlib.sha256).hexdigest()


def beacon_signature(packet):
    return mac(json.dumps({k: v for k, v in packet.items() if k != "signature"}, sort_keys=True, separators=(",", ":")))


def trusted_beacon(packet):
    signature = packet.get("signature", "")
    return bool(PEER_SECRET and isinstance(signature, str) and re.fullmatch(r"[0-9a-f]{64}", signature) and hmac.compare_digest(signature, beacon_signature(packet)))


def request_headers(method, raw_path, body=b""):
    if not PEER_SECRET:
        return {}
    stamp, nonce = str(int(time.time())), uuid.uuid4().hex
    payload = "\n".join((method.upper(), raw_path, stamp, nonce, hashlib.sha256(body).hexdigest()))
    return {"X-LANPool-Peer-Time": stamp, "X-LANPool-Peer-Nonce": nonce, "X-LANPool-Peer-Signature": mac(payload)}


def verify_request(method, raw_path, body, headers, replay_cache):
    try:
        stamp, nonce, signature = (headers[k] for k in ("X-LANPool-Peer-Time", "X-LANPool-Peer-Nonce", "X-LANPool-Peer-Signature"))
        if not PEER_SECRET or abs(time.time() - int(stamp)) > 30 or len(nonce) != 32:
            return False
        payload = "\n".join((method, raw_path, stamp, nonce, hashlib.sha256(body).hexdigest()))
        if not hmac.compare_digest(signature, mac(payload)) or nonce in replay_cache:
            return False
        for key, value in list(replay_cache.items()):
            if time.time() - value > 60:
                replay_cache.pop(key, None)
        if len(replay_cache) >= 4096:
            return False
        replay_cache[nonce] = time.time()
        return True
    except (KeyError, ValueError, TypeError):
        return False


def sign_content(sha):
    return mac("content:" + sha) if PEER_SECRET else ""


def verify_content(sha, signature):
    return bool(PEER_SECRET and isinstance(signature, str) and re.fullmatch(r"[0-9a-f]{64}", signature) and hmac.compare_digest(signature, sign_content(sha)))


def signed_request(client, method, url, **kwargs):
    request = client.build_request(method, url, **kwargs)
    request.headers.update(request_headers(method, request.url.raw_path.decode("ascii"), request.content))
    return request


async def read_bounded(response, limit=65536):
    body = bytearray()
    async for block in response.aiter_bytes(chunk_size=4096):
        body.extend(block)
        if len(body) > limit:
            raise ValueError("Peer metadata/error response exceeded its limit")
    return bytes(body)


async def send_bounded(client, request):
    response = await client.send(request, stream=True)
    try:
        content = await read_bounded(response)
        import httpx
        return httpx.Response(response.status_code, headers=response.headers, content=content, request=request)
    finally:
        await response.aclose()


def peer_url(peer, path):
    scheme = peer.get("scheme", "http")
    if scheme not in ("http", "https"):
        raise ValueError("Invalid peer transport")
    return f"{scheme}://{peer.get('ip') or peer['lan_ip']}:{peer.get('port') or peer['http_port']}{path}"


def peer_client(timeout):
    import httpx
    context = ssl.create_default_context(cafile=os.environ.get("LANPOOL_CA_FILE") or None)
    return httpx.AsyncClient(timeout=timeout, trust_env=False, verify=context)
