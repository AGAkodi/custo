# Phase 5: datasets, flow signals and SOC export

## Public dataset adapters

The Data & SOC screen and `POST /api/datasets/analyze` accept up to 1 MB and 1,000 rows of headered CSV. Choose `unsw-nb15` for the UNSW-NB15 **training/testing** CSV schema (`dur,spkts,dpkts,sbytes,dbytes,label,attack_cat`) or `cicids2017` for the CICIDS2017 flow CSV schema (`Flow Duration,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Label`). Header whitespace is trimmed. Other files, variants and missing fields are rejected; this is not a general CSV mapper. A CSV must be UTF-8.

Bundled `backend/fixtures/unsw-example.csv` and `cicids2017-example.csv` are invented schema examples, not rows from the datasets. Acquire actual public datasets separately and follow their terms and citation requirements. Source references: [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) and [CIC datasets](https://www.unb.ca/cic/datasets/).

These are network flows, not authentication logs. No IP addresses, timestamps, accounts, or authentication events are invented where the source lacks them. Dataset labels are hidden by default and, when explicitly requested, are presented only as source labels; they never influence classification or become confirmed feedback. Each import stores only its format, SHA-256, row count and aggregate classifications in HydraDB; raw CSV and dataset labels are not persisted. The original file must be retained separately for reproduction.

Two exploratory heuristics add `high_outbound_volume` (at least 100,000,000 source bytes in a flow) and `high_packet_rate` (at least 200 packets at 10,000 packets/second). Other flows return `no_flow_rule_match`. These are observable signals, not proof of exfiltration or denial-of-service; thresholds are uncalibrated and may produce false positives and false negatives. No accuracy claim is made.

## Sigma export

`GET /api/rules/baseline-single-source-v1/sigma` downloads an experimental two-document Sigma bundle: a normalized login failure event rule and an event-count correlation (10 failures, 10 minutes, grouped by `source_ip`). The bundle passes the pySigma 2.1 parser. It is an **approximation**: Custos first selects its densest global event window, whereas Sigma groups per source. Target engines may also use different window semantics. Map the custom Custos `result` and `source_ip` fields to real logs, inspect the target query, and validate independently. Unsupported rules, including the adaptive distributed rule, return 422 rather than a misleading export. See the [Sigma correlation specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html).

## Splunk HEC

An optional integration produces a Splunk HEC JSON envelope for a stored authentication assessment. `GET /api/integrations/splunk/preview/{decision_id}` requires the reviewer token and displays the payload. It includes decision metadata, classification, rule and memory references, and evidence event IDs, but not raw events, IPs, account names, or HEC credentials. Configure `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN` on the server only; the endpoint must be HTTPS and end in `/services/collector/event`. The Data & SOC screen shows the configured destination before the user explicitly confirms sending. The server never sends automatically, follows no redirects and makes no automatic retries. A HEC success response means accepted, not indexed; indexing acknowledgements are not polled. Errors can be ambiguous and retrying may duplicate an event. Delivery auditing and retry queues are not yet implemented.

The HEC payload and mock transport are tested, but no real Splunk instance or credentials were supplied, so a live delivery has not been validated. The integration is currently outbound only; there is no Splunk search, SIEM ingestion, or automatic response. See [Splunk HEC documentation](https://help.splunk.com/en/splunk-enterprise/get-data-in/collect-http-event-data/set-up-and-use-http-event-collector-in-splunk-web).
