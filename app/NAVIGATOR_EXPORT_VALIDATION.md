# Navigator Export Validation

This build validates the Navigator layer JSON objects before writing report exports.

Navigator-importable files:

- `exports/<job_id>/mitre_navigator_layer.json`
- `exports/<job_id>/mitre_unified_coverage_layer.json`
- `exports/<job_id>/mitre_data_source_coverage_layer.json`

Each Navigator layer is generated with:

- `domain: enterprise-attack`
- `versions.layer: 4.5`
- `techniques` as a Navigator-compatible list
- valid technique IDs/tactics from the loaded ATT&CK dataset
- Navigator-compatible colors, scores, legend, and metadata

Application data files that should not be imported into Navigator:

- `reports/<job_id>/enterprise_attack_coverage.json`
- `reports/<job_id>/enterprise_attack_coverage_model.json`

The Reports tab and Report Guide identify which files are Navigator layers and which files are app data.
