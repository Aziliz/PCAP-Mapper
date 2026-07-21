# Environment Profiles

PCAP Mapper now defines environment profiles centrally in `app/telemetry/registry.py`.

Profiles are advisory groupings of telemetry categories and priority plugins. The Telemetry page auto-selects the best profile for the active job by scoring observed plugin aliases, observed categories, and profile-specific signals found in detected log sources, normalized events, flows, assets, and processed files.

Profiles currently included:

- Windows Enterprise
- Linux Server
- macOS Fleet
- Network Monitoring
- Cloud Hybrid
- Identity-Centric
- EDR-heavy
- Container Platform
- OT/ICS
- SaaS Collaboration
- Database Monitoring
- DevOps Platform

Auto-selection does not create evidence and does not inflate observed coverage. It only explains which telemetry profile best matches the active job and helps prioritize plugin validation, recommendations, and gaps.
