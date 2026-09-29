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

## Validation audit findings (2026-09-29)

- SQLite alert persistence uses parameterized SQL for variable values; no dynamic SQL injection path was found in the reviewed alert store.
- PCAP uploads are streamed to a temporary file and bounded by `IPXDR_MAX_UPLOAD_MB` (default 200 MB); only `.pcap`, `.pcapng`, and `.cap` names are accepted.
- Malformed PCAP errors were changed to a generic client-facing message so parser/library internals and local paths are not disclosed.
- Administrative training endpoints remain protected by `IPXDR_ADMIN_TOKEN` when configured. They should not be exposed on an untrusted interface.
- The API binds to loopback in the validated demo command (`127.0.0.1:8000`).
- WebSocket runtime support is now an explicit `websockets>=13` dependency and the `/ws/alerts` handshake was verified in the live browser smoke test.
- Dependency review found available package updates in the current environment. No automatic upgrade was applied during this validation pass; dependency changes should be reviewed/tested as a separate maintenance task.
- No intrusive external scanning was performed; security validation stayed within the local authorized lab target.
