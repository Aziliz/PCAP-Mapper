"""Event normalization package for PCAP Mapper v2.

The normalizer converts packet-derived flow events and forwarded log payloads
into stable, platform-neutral event dictionaries consumed by later ATT&CK,
rule, and reporting stages.
"""

from .normalizer import normalize_event, summarize_normalized_events
