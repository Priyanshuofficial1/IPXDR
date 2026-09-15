# Architecture

```text
                ONE-WAY TRAFFIC
                       |
                 DATA DIODE/TAP
                       |
                 READ-ONLY INGEST
                       |
                 FLOW NORMALIZER
                       |
                  FEATURE ENGINE
              /          |          \\
        BEHAVIORAL    TEMPORAL     GRAPH
           |              |           |
           +--------------+-----------+
                          |
                    AI DETECTION CORE
                 /          |          \\
           SUPERVISED    ANOMALY    STATISTICAL
                 \\          |          /
                          |
                      RISK FUSION
                          |
                    EXPLAINABLE ALERT
                          |
                     SOC DASHBOARD
```

## Passive invariant
The monitoring components must not initiate traffic toward monitored source/destination systems. Ingestion is observational only.
