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
- HMAC proves group membership/integrity. TLS/VPN is needed for confidentiality;
  compromised enrolled members remain trusted until you rotate their group key.
- Retry starts again from the beginning. Partial resume requires a persistent
  verified chunk manifest and is not implemented or claimed.
- Cold cache indexing uses metadata to avoid hashing all files, but each served
  or copied cache file is hashed before use. This adds disk I/O for large hits.
- Active readers can temporarily prevent new cache registration; completed files
  are retained in the downloads folder when registration cannot fit them.
- Single-PC tests do not validate a campus firewall, actual multi-link WAN,
  multi-gigabyte sustained load, or real-game latency. Configure certificates and
  firewall rules for your environment. IPv4 is used for peer discovery/manual entry.
