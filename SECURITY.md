# Security model

LANPool is for an enrolled, trusted group on a private LAN/VPN. It is not an
Internet-facing untrusted file-sharing service. A machine owner and any holder of
the peer group key are trusted. Compromised group members can deny service; use a
publisher-trusted expected SHA-256 to reject substituted content.

- Default HTTP binding is localhost. Binding elsewhere requires an admin token,
  a peer group secret, and a TLS certificate/key. Explicit
  `LANPOOL_ALLOW_INSECURE_LAN=1` permits HTTP on an intentionally trusted network.
- The admin token is local to its node. Only signed peer requests are sent to
  peer endpoints. Peer signatures are accepted only on the narrow worker/cache/
  boost-notification route set, not administrative job/settings endpoints.
- Signed requests cover method, encoded path/query, timestamp, nonce, and body
  digest. Replay nonces expire and their cache is bounded. Beacons are signed;
  malformed types, out-of-range shares, and non-finite timestamps are rejected.
- Manual pairing checks a fresh challenge and signed health body before trusting
  the endpoint. A LAN address cannot overwrite a manually configured address.
- SHA-256 digests on helper/cache payloads are authenticated by the group key;
  received bytes must match them. TLS adds confidentiality, certificate-based
  endpoint verification, and protection for admin traffic. Configure a private CA
  using `LANPOOL_CA_FILE`; no certificate-verification bypass exists.
- Origin URLs default to public HTTP(S) destinations. Loopback/private origins
  need separate explicit switches. Link-local/metadata, unspecified, multicast,
  reserved addresses, URL credentials, and unsafe redirect targets are rejected.
  Connections use the validated IP, original HTTP Host, and original TLS hostname;
  DNS is not resolved again by the transport. Proxies from the environment are
  disabled for origin/peer network clients.
- Missing/weak ETags cannot authorize URL cache reuse. Multi-chunk assembly needs
  a strong ETag or an expected final hash. All range offsets/totals are verified.
- Cache paths are contained, SHA-only serving is enforced, copies/streams verify
  content, and active files cannot be renamed or evicted through the cache API.
- Helper concurrency, network body sizes, metadata responses, history, peer
  registry, replay cache, cache quota, and pending download grants are bounded.
- JSON request bodies are limited to 64 KiB before parsing/authentication, and
  unauthenticated local administration also checks the Host to reject rebinding.
- Browser grants expire after 30 seconds, authorize one hash, and are single use.
  Keep access logs private: they can contain a short-lived already-consumed grant.
- Local unauthenticated administration is restricted to loopback callers and
  same-origin browser requests. Set an admin token if other local users/processes
  are outside your trust boundary. Do not open untrusted sites while running an
  unauthenticated local service.

Rotate the group key on all nodes after removing a group member. Never commit
credentials, TLS private keys, runtime indexes/history, downloaded content, or
machine-specific logs. `.gitignore` excludes the standard local artifacts. TLS
and real campus firewall/network behavior require deployment-specific validation.
