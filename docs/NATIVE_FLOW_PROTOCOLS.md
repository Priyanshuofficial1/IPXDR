# Native flow protocol ingestion

IPXDR now includes **offline, read-only binary decoders** for common IPFIX v10 and sFlow v5 flow records.

## IPFIX

`backend.ingestion.ipfix.IPFIXDecoder` maintains templates by observation domain/template ID and decodes common IEs including source/destination IPv4, ports, protocol, bytes, packets, TCP flags and export timestamps.

Unsupported or enterprise-specific fields are safely ignored. Template withdrawal/options templates and vendor-specific semantics are not interpreted as application-level features.

## sFlow

`backend.ingestion.sflow.SFlowDecoder` accepts sFlow v5 datagrams and extracts flow samples containing raw Ethernet IPv4/IPv6 packet headers. It derives the passive five-tuple and observed frame length.

This is intentionally an offline decoder: IPXDR does not open an sFlow/IPFIX listener or transmit control traffic. A collector/forwarder can hand datagrams to the decoder inside the monitoring enclave.

## Limitations

- IPFIX variable-length fields, options-template semantics and arbitrary enterprise IEs are not fully normalized.
- sFlow counter samples and non-raw flow-record formats are not converted into `FlowEvent` yet.
- Direction is `unknown` unless supplied by an upstream exporter.
- The decoder does not reconstruct payloads or decrypt encrypted sessions.
