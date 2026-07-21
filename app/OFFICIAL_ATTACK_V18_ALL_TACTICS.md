# Official ATT&CK Enterprise v18 all-tactics rule coverage

This build verifies rule coverage from the ATT&CK technique registry loaded by `app.attack.stix_dataset`.

Preferred source:

- Official MITRE ATT&CK Enterprise v18.0 STIX 2.1 release asset: `https://github.com/mitre-attack/attack-stix-data/releases/download/v18.0/enterprise-attack.json`

Runtime behavior:

- If `ATTACK_STIX_PATH` is set, the app loads that local official STIX JSON file.
- Otherwise, if `ATTACK_STIX_AUTO_DOWNLOAD=1`, the app attempts to download the official v18.0 Enterprise STIX file.
- If `ATTACK_STIX_STRICT=1`, startup/report generation fails if the official STIX dataset cannot be loaded.
- The generated rule coverage report now covers all loaded ATT&CK Enterprise tactics, techniques, and sub-techniques, not only a manually maintained subset.

Generated coverage hooks:

- Existing built-in/custom rules are reused when they already map to a technique/sub-technique.
- Only missing ATT&CK IDs receive generated coverage rules.
- Generated rules are marked with IDs beginning with `official-v18-`.
- The machine-readable report is exported as `attack_v18_rule_coverage_report.json`.

Recommended strict run command:

```bash
docker run --rm --name pcap-mapper \
  -p 8000:8000 \
  -e ATTACK_STIX_STRICT=1 \
  -e ATTACK_STIX_AUTO_DOWNLOAD=1 \
  -v "$PWD/uploads:/app/uploads:Z" \
  -v "$PWD/results:/app/results:Z" \
  pcap-mapper
```

For offline environments, download the official v18.0 `enterprise-attack.json` file separately and run with:

```bash
-e ATTACK_STIX_STRICT=1 \
-e ATTACK_STIX_PATH=/app/attack-data/enterprise-attack.json \
-v "$PWD/attack-data:/app/attack-data:Z"
```
