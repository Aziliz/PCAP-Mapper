# PCAP Mapper v2.56 patch notes

- Hardened upload-pipeline ATT&CK mapping for simulated PCAP payloads by preserving longer Raw payload hints and extracting explicit ATT&CK technique IDs from normalized event text.
- Fed normalized-event source/provider/channel/product strings back into detected log-source expansion so simulated telemetry sources map into the source-only STIX coverage path.
- Reordered pipeline stage metadata to keep Storage Policy before Flow Reconstruction and Rule Evaluation before ATT&CK Mapping / Coverage Model.
- Updated MITRE heat-map and Navigator/report colors: Observed = red, Validated = yellow, Covered/Theoretical = green.
