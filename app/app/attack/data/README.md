# Bundled ATT&CK STIX data

PCAP Mapper includes selectable Enterprise ATT&CK STIX bundle files for v13 through v19:

- `enterprise-attack-13.0.json`
- `enterprise-attack-14.0.json`
- `enterprise-attack-15.0.json`
- `enterprise-attack-16.0.json`
- `enterprise-attack-17.0.json`
- `enterprise-attack-18.0.json` (default)
- `enterprise-attack-19.0.json`

These offline bundles allow the version selector and STIX-only coverage pipeline to work without internet access. For compliance-critical or version-exact use, replace any bundled file with the official MITRE Enterprise ATT&CK `enterprise-attack.json` release for that version, keeping the same filename.

Runtime overrides are also supported:

- `ATTACK_STIX_PATH=/path/to/enterprise-attack.json`
- `ATTACK_STIX_V18_PATH=/path/to/enterprise-attack-v18.json`
- `ATTACK_STIX_V19_PATH=/path/to/enterprise-attack-v19.json`

Theoretical coverage in the STIX engine is source-only: detected log sources are mapped through the selected bundle's STIX `x_mitre_data_sources` metadata into ATT&CK techniques. OS baselines and product deployment assumptions do not add theoretical coverage.
