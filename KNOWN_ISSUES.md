# Operational limits and supported behavior

The original audit findings are tracked with their resolutions in [FIXES.md](FIXES.md).
This file records remaining design constraints rather than obsolete defects.

- A shared saturated router uplink does not gain capacity from more helpers.
  Use `scripts/benchmark.py` to compare equal concurrency on your actual topology.
- QoS is an application-level shared-byte budget, not an OS/router scheduler or
  a guarantee about game ping. Gaming detection matches process names, not windows.
- The baseline sharing capacity is configured, not measured automatically. Helper
  ingress and egress both consume it; the effective end-to-end helper throughput
  can be lower than the displayed budget. User-initiated requester downloads are
  outside that budget.
- Online cache lookup probes the origin; expected-hash offline mode uses only
  this node's verified cache. Missing/weak ETags cannot authorize URL cache reuse.
- Helper byte counters cover successful chunks, not wire overhead or every lost
  helper retry. They do not measure all WAN use by the entire LAN.
- HMAC proves group membership, not honesty. Production peer content requires an
  independent trusted expected SHA-256 by default. `LANPOOL_TRUST_GROUP_CONTENT=1`
  deliberately waives that requirement for a trusted group (used by the local demo).
  TLS/VPN is still needed for confidentiality; rotate keys after member compromise.
- Retry starts again from the beginning. Partial resume requires a persistent
  verified chunk manifest and is not implemented or claimed.
- Cold cache indexing uses metadata to avoid hashing all files, but each served
  or copied cache file is hashed before use. This adds disk I/O for large hits.
- Completed files always remain in downloads; the independent cache copy can be
  skipped for insufficient quota/free space or pinned active readers. Account for
  the extra disk space. LRU access timestamps are batched; a forced crash may lose
  the most recent two seconds of access history.
- Single-PC tests do not validate a campus firewall, actual multi-link WAN,
  multi-gigabyte sustained load, or real-game latency. Configure certificates and
  firewall rules for your environment. IPv4 is used for peer discovery/manual entry.
