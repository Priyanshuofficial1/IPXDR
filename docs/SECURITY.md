# Security Boundary

## Passive invariant
IPXDR is a monitor. It parses observations and produces local analytics; it does not probe, handshake with, block, or transmit traffic to monitored endpoints. TLS/QUIC handling is metadata-only and does not decrypt payloads.

## API hardening
The API exposes training endpoints for controlled model lifecycle operations. Set `IPXDR_ADMIN_TOKEN` before exposing the API outside a trusted local monitoring enclave. Clients must send it in `X-IPXDR-Admin-Token` for `/anomaly/fit` and `/supervised/fit`.

If the token is unset, training endpoints remain enabled for local development compatibility. For deployed environments, configure a token and restrict network access at the host/container boundary.

Recommended deployment controls:
- bind the development server to `127.0.0.1` unless remote access is explicitly required;
- put authentication/TLS and network policy in front of a remotely exposed API;
- keep the monitoring interface isolated from monitored source/destination networks;
- do not mount packet captures or model artifacts writable by untrusted users;
- treat model outputs as evidence indicators, not proof of compromise.
