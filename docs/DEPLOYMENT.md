# Deployment

## Local
`python -m pip install -e '.[test]'`
`uvicorn backend.api.main:app --host 127.0.0.1 --port 8000`

## Docker
`docker compose up --build`

The monitor is passive: ingest PCAP/flow metadata; never transmit monitored traffic. Put the API/dashboard on the monitoring enclave only.
