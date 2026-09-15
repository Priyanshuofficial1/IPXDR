# Deployment

## Local
`python -m pip install -e '.[test]'`
`uvicorn backend.api.main:app --host 127.0.0.1 --port 8000`

## Docker
`docker compose up --build`

The monitor is passive: ingest PCAP/flow metadata; never transmit monitored traffic. Put the API/dashboard on the monitoring enclave only.


## Persistent Docker deployment

`docker-compose.yml` persists SQLite alerts and model artifacts in the `ipxdr-data` volume and binds the API to localhost by default. Set `IPXDR_ADMIN_TOKEN` before deployment. The monitoring interface should remain inside the trusted enclave; do not expose training endpoints directly to untrusted networks.
