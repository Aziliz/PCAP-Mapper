import csv, json, time, textwrap
from pathlib import Path
from app.config import REPORT_DIR, EXPORT_DIR
from app.attack.versioned import strict_navigator_layer, strict_data_source_coverage_layer, strict_unified_coverage_layer, build_data_source_coverage, enterprise_coverage_assessment, ATTACK_DATASET_METADATA, build_enterprise_attack_coverage_model, validate_layer, telemetry_capability_assessment
from app.utils import write_json
from app.rules.engine import load_rules, build_validation_results, attack_coverage_report
from app.coverage_cache import ensure_coverage_cache


def _analysis_configuration(result):
    return {
        'analysis_mode': result.get('analysis_mode') or result.get('mode') or 'Production',
        'attack_source': result.get('attack_source') or result.get('attack_mode') or ATTACK_DATASET_METADATA.get('dataset_label') or 'ATT&CK Enterprise v18 STIX',
        'attack_dataset_source': ATTACK_DATASET_METADATA.get('source'),
        'attack_dataset_path': ATTACK_DATASET_METADATA.get('path'),
        'rule_validation_status': result.get('rule_validation_status', 'not_run'),
        'event_parsing_enabled': True,
        'normalized_event_count': len(result.get('normalized_events', []) or []),
        'mapped_event_count': len([e for e in result.get('normalized_events', []) or [] if e.get('attack_candidates')]),
        'validation_source': 'flows + normalized events',
        'coverage_scope': (result.get('enterprise_coverage') or {}).get('coverage_scope', []),
    }


def _escape_pdf_text(text):
    return str(text or '').replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)').replace('\r', ' ').replace('\n', ' ')


def _write_simple_pdf(path, title, lines):
    """Write a small, standards-compliant text PDF using only stdlib."""
    wrapped = []
    for line in lines:
        if line == '':
            wrapped.append('')
        else:
            wrapped.extend(textwrap.wrap(str(line), width=92) or [''])
    pages = []
    per_page = 46
    for i in range(0, len(wrapped), per_page):
        pages.append(wrapped[i:i+per_page])
    if not pages:
        pages = [['No content.']]
    objects = []
    objects.append('<< /Type /Catalog /Pages 2 0 R >>')
    kids = ' '.join(f'{3 + idx*2} 0 R' for idx in range(len(pages)))
    objects.append(f'<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>')
    for idx, page_lines in enumerate(pages):
        page_obj = 3 + idx*2
        content_obj = page_obj + 1
        objects.append(f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> /F2 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >> >> >> /Contents {content_obj} 0 R >>')
        stream = ['BT', '/F2 15 Tf', '50 750 Td', f'({_escape_pdf_text(title)}) Tj', '/F1 9 Tf', '0 -22 Td']
        for line in page_lines:
            stream.append(f'({_escape_pdf_text(line)}) Tj')
            stream.append('0 -14 Td')
        stream.append('ET')
        data = '\n'.join(stream)
        objects.append(f'<< /Length {len(data.encode("latin-1", "replace"))} >>\nstream\n{data}\nendstream')
    out = ['%PDF-1.4']
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(sum(len(x.encode('latin-1', 'replace')) + 1 for x in out))
        out.append(f'{i} 0 obj')
        out.append(obj)
        out.append('endobj')
    xref_pos = sum(len(x.encode('latin-1', 'replace')) + 1 for x in out)
    out.append('xref')
    out.append(f'0 {len(objects)+1}')
    out.append('0000000000 65535 f ')
    for off in offsets[1:]:
        out.append(f'{off:010d} 00000 n ')
    out.append('trailer')
    out.append(f'<< /Size {len(objects)+1} /Root 1 0 R >>')
    out.append('startxref')
    out.append(str(xref_pos))
    out.append('%%EOF')
    path.write_bytes(('\n'.join(out) + '\n').encode('latin-1', 'replace'))


def _write_potential_coverage_reports(job_report, potential):
    lines = []
    lines.append('Potential ATT&CK Coverage Assessment')
    lines.append('')
    lines.append(f"ATT&CK version: {potential.get('attack_version','')}")
    lines.append(f"Coverage engine: {potential.get('coverage_engine','')}")
    lines.append(f"Detected log sources: {', '.join(potential.get('detected_log_sources') or []) or 'none'}")
    lines.append(f"Applicable techniques: {potential.get('applicable_technique_count', 0)}")
    lines.append(f"Observed telemetry coverage: {potential.get('observed_telemetry_score', 0)}% ({potential.get('observed_telemetry_technique_count', 0)} techniques)")
    lines.append(f"Potential coverage: {potential.get('potential_score', 0)}% ({potential.get('potential_technique_count', 0)} techniques)")
    lines.append(f"Potential increase: +{potential.get('potential_increase_score', 0)}% / +{potential.get('potential_increase_techniques', 0)} techniques")
    lines.append('')
    lines.append('How to read this report: Observed telemetry coverage is strict and based on detected log sources mapped through ATT&CK data-source metadata. Potential coverage shows additional ATT&CK techniques that the same detected telemetry products could support if their richer event types, modules, or protocol logs are enabled and forwarded.')
    for row in potential.get('product_rows') or []:
        lines.append('')
        lines.append(f"Telemetry Source: {row.get('source')} ({row.get('category')})")
        lines.append(f"Potential increase: +{row.get('additional_technique_count', 0)} techniques")
        lines.append(f"Observed components: {', '.join((row.get('observed_components') or [])[:18]) or 'none'}")
        lines.append(f"Potential components: {', '.join((row.get('potential_components') or [])[:24]) or 'none'}")
        if row.get('additional_techniques'):
            lines.append(f"Sample additional techniques: {', '.join(row.get('additional_techniques')[:20])}")
        lines.append(f"Recommendation: {row.get('recommendation','')}")
    md = ['# Potential ATT&CK Coverage Assessment', ''] + lines[2:]
    (job_report / 'potential_attack_coverage.md').write_text('\n'.join(md))
    html = ['<html><head><title>Potential ATT&CK Coverage Assessment</title><style>body{font-family:Arial,sans-serif;line-height:1.45;margin:28px}h1,h2{color:#123}.card{border:1px solid #ccd;padding:12px;border-radius:8px;margin:10px 0;background:#f8fafc}</style></head><body>']
    html.append('<h1>Potential ATT&CK Coverage Assessment</h1>')
    html.append(f"<p><b>Observed telemetry coverage:</b> {potential.get('observed_telemetry_score', 0)}% &nbsp; <b>Potential coverage:</b> {potential.get('potential_score', 0)}% &nbsp; <b>Increase:</b> +{potential.get('potential_increase_score', 0)}%</p>")
    html.append('<p>This report separates strict observed-log-source theoretical coverage from potential capability coverage for detected telemetry products.</p>')
    for row in potential.get('product_rows') or []:
        html.append('<div class="card">')
        html.append(f"<h2>{row.get('source')} ({row.get('category')})</h2>")
        html.append(f"<p><b>Potential increase:</b> +{row.get('additional_technique_count',0)} techniques</p>")
        html.append(f"<p><b>Observed components:</b> {', '.join((row.get('observed_components') or [])[:30]) or 'none'}</p>")
        html.append(f"<p><b>Potential components:</b> {', '.join((row.get('potential_components') or [])[:40]) or 'none'}</p>")
        html.append(f"<p><b>Recommendation:</b> {row.get('recommendation','')}</p>")
        html.append('</div>')
    html.append('</body></html>')
    (job_report / 'potential_attack_coverage.html').write_text(''.join(html))
    _write_simple_pdf(job_report / 'potential_attack_coverage.pdf', 'Potential ATT&CK Coverage Assessment', lines)


def generate_reports(job_id, result, ctx=None):
    job_report = REPORT_DIR / job_id
    job_export = EXPORT_DIR / job_id
    job_report.mkdir(parents=True, exist_ok=True)
    job_export.mkdir(parents=True, exist_ok=True)

    rules = load_rules()
    validations = result.get('rule_validations') or build_validation_results(result, rules)
    result['rule_validations'] = validations
    result['validated_techniques'] = validations.get('validated_techniques', [])
    result, _coverage_rebuilt = ensure_coverage_cache(result, rules)
    coverage = result.get('data_source_coverage') or []
    enterprise = result.get('enterprise_coverage') or {}
    coverage_model = result.get('enterprise_attack_coverage_model') or {}
    config = _analysis_configuration(result)
    potential = telemetry_capability_assessment(result)

    write_json(job_report / 'analysis.json', result)

    md = ['# PCAP Analysis Report', '', f"Generated: {time.ctime()}", '', '## Analysis Configuration']
    for k, v in config.items():
        md.append(f'- {k}: {v}')
    md += ['', '## Summary']
    for k, v in result.get('summary', {}).items():
        md.append(f'- {k}: {v}')
    md += ['', '## How to Use This Report']
    md.append('- Start with Enterprise ATT&CK Coverage to understand observed, theoretical, detectable, validated, and not-applicable coverage in the detected OS/log-source scope.')
    md.append('- Review Key Findings and ATT&CK Evidence to understand what activity was actually seen.')
    md.append('- Use Normalized Event Summary when forwarded logs were captured inside PCAP traffic.')
    md.append('- Use Coverage Gaps and Recommendations to decide what telemetry or rules to add next. Recommendations are limited to the detected OS/log-source scope.')
    md.append('- Use CSV/JSON/NDJSON exports for SIEM ingestion, evidence review, or sharing with another analyst.')
    md += ['', '## Analysis Highlights']
    md.append(f"- Hosts: {len(result.get('hosts', []) or [])}")
    md.append(f"- Flows: {len(result.get('flows', []) or [])}")
    md.append(f"- Findings: {len(result.get('findings', []) or [])}")
    md.append(f"- Log sources: {len(result.get('log_sources', []) or [])}")
    md.append(f"- Normalized events: {len(result.get('normalized_events', []) or [])}")
    md += ['', '## Enterprise ATT&CK Coverage']
    md.append(f"- Overall scoped coverage: {enterprise.get('overall_score', 0)}%")
    md.append(f"- Maturity: {enterprise.get('maturity', 'None')}")
    md.append(f"- Detected scope: {', '.join(enterprise.get('coverage_scope', []) or [])}")
    md.append(f"- Scoped technique denominator: {enterprise.get('scoped_technique_total', 0)}")
    md.append(f"- Observed techniques: {coverage_model.get('observed_count', 0)}")
    md.append(f"- Theoretical techniques: {coverage_model.get('theoretical_count', 0)}")
    md.append(f"- Detectable techniques: {coverage_model.get('detectable_count', 0)}")
    md.append(f"- Validated techniques: {coverage_model.get('validated_count', 0)}")
    md.append(f"- Out-of-scope validated matches ignored: {coverage_model.get('out_of_scope_validated_count', 0)}")
    md.append('- Environment-scoped overlay coloring: applicable/theoretical/observed/detectable/not-covered/not-applicable only; validation is reported as card/report metadata, not as a separate overlay color.')
    md += ['', '### Coverage by Tactic']
    for label, key in [('Observed', 'observed'), ('Theoretical', 'theoretical'), ('Validated', 'validated')]:
        md.append(f"#### {label}")
        for row in (coverage_model.get('rollups', {}) or {}).get(key, []):
            md.append(f"- {row.get('name')}: {row.get('score', 0)}% ({row.get('covered', 0)}/{row.get('total', 0)})")
    md += ['', '### Potential ATT&CK Coverage']
    md.append(f"- Observed telemetry coverage: {potential.get('observed_telemetry_score', 0)}%")
    md.append(f"- Potential coverage: {potential.get('potential_score', 0)}%")
    md.append(f"- Potential increase: +{potential.get('potential_increase_score', 0)}% / +{potential.get('potential_increase_techniques', 0)} techniques")
    md.append('- See potential_attack_coverage.pdf/html/md for product-by-product configuration opportunities.')
    md += ['', '### Coverage Gaps and Recommendations']
    for g in enterprise.get('gaps', [])[:20]:
        md.append(f"- Gap: {g.get('tactic')}: {g.get('gap')} ({g.get('coverage')}%)")
    if not enterprise.get('gaps'):
        md.append('- No major scoped gaps identified.')
    for r in enterprise.get('recommendations', [])[:20]:
        md.append(f"- Recommendation: {r.get('source')} (+{r.get('gain')}% estimated): {r.get('reason')}")
    if not enterprise.get('recommendations'):
        md.append('- No telemetry recommendations are available for the detected OS/log-source scope.')
    md += ['', '### Detectable ATT&CK Coverage']
    for t in [x for x in coverage_model.get('techniques', []) if x.get('detectable')][:300]:
        md.append(f"- {t.get('techniqueID')} {t.get('name')} ({t.get('tactic')}): enabled rule exists but no matching evidence was recorded")
    md += ['', '### Environment-Scoped Overlay Technique Status']
    for t in [x for x in coverage_model.get('techniques', []) if x.get('applicable')][:300]:
        md.append(f"- {t.get('techniqueID')} {t.get('name')} ({t.get('tactic')}): state={t.get('state')}; rule={bool(t.get('rule'))}; validated={bool(t.get('validated'))}; observed={bool(t.get('observed'))}; theoretical={bool(t.get('theoretical'))}")
    ignored = [x for x in coverage_model.get('techniques', []) if x.get('out_of_scope_validated_match')]
    if ignored:
        md += ['', '### Out-of-Scope Validated Matches Ignored']
        for t in ignored[:100]:
            md.append(f"- {t.get('techniqueID')} {t.get('name')} ({t.get('tactic')}): validation match was ignored because the technique is outside the detected OS/log-source scope")
    md += ['', '### Validated ATT&CK Evidence']
    for t in [x for x in coverage_model.get('techniques', []) if x.get('validated')][:300]:
        ev = '; '.join(t.get('validated_evidence', [])[:3])
        rules_txt = ', '.join(t.get('validated_rules', [])[:5])
        md.append(f"- {t.get('techniqueID')} {t.get('name')} ({t.get('tactic')}): rules={rules_txt}; evidence={ev}")
    md += ['', '## Top Protocols']
    for k, v in sorted(result.get('protocols', {}).items(), key=lambda x: x[1], reverse=True)[:20]:
        md.append(f'- {k}: {v}')
    md += ['', '## Top Assets']
    for h in (result.get('hosts', []) or [])[:50]:
        md.append(f"- {h.get('ip','')} role={h.get('role','')} bytes={h.get('bytes','')} protocols={h.get('protocols','')}")
    md += ['', '## Top Communications']
    for f in sorted(result.get('flows', []) or [], key=lambda x: int(x.get('bytes') or 0), reverse=True)[:50]:
        md.append(f"- {f.get('src_ip','')} -> {f.get('dst_ip','')} {f.get('protocol','')}:{f.get('dport','')} packets={f.get('packets',0)} bytes={f.get('bytes',0)}")
    md += ['', '## Normalized Event Summary']
    evs = result.get('normalized_events', []) or []
    summary = result.get('normalized_event_summary', {}) or {}
    md.append(f"- Normalized events: {len(evs)}")
    md.append(f"- Events mapped to ATT&CK: {len([e for e in evs if e.get('attack_candidates')])}")
    for k, v in (summary.get('by_log_source') or {}).items():
        md.append(f'- Log source {k}: {v}')
    md += ['', '## Event-Derived ATT&CK Evidence']
    for e in [x for x in evs if x.get('attack_candidates')][:200]:
        md.append(f"- {', '.join(e.get('attack_candidates') or [])}: {e.get('log_source')} / {e.get('event_type')} host={e.get('host')} evidence={(e.get('raw') or '')[:160]}")
    md += ['', '## Findings']
    for f in result.get('findings', [])[:200]:
        md.append(f"- **{f.get('severity','')}** {f.get('title','')}: {f.get('evidence','')}")
    (job_report / 'report.md').write_text('\n'.join(md))

    html_parts = ['<html><head><title>PCAP Report</title><style>body{font-family:Arial,sans-serif;line-height:1.45;margin:28px}h1,h2,h3{color:#123}p{margin:.35rem 0}.metric{display:inline-block;padding:10px 14px;margin:4px;border:1px solid #ccc;border-radius:8px;background:#f8fafc}</style></head><body>']
    for line in md:
        if line.startswith('# '): html_parts.append(f'<h1>{line[2:]}</h1>')
        elif line.startswith('## '): html_parts.append(f'<h2>{line[3:]}</h2>')
        elif line.startswith('### '): html_parts.append(f'<h3>{line[4:]}</h3>')
        elif line.startswith('#### '): html_parts.append(f'<h4>{line[5:]}</h4>')
        elif line.startswith('- '): html_parts.append(f'<p>&bull; {line[2:]}</p>')
        elif line.strip(): html_parts.append(f'<p>{line}</p>')
    html_parts.append('</body></html>')
    html = ''.join(html_parts)
    (job_report / 'report.html').write_text(html)
    with open(job_report / 'hosts.csv', 'w', newline='') as f:
        rows = result.get('hosts', [])
        w = csv.DictWriter(f, fieldnames=['ip','macs','role','bytes','protocols','first_seen','last_seen'])
        w.writeheader()
        for row in rows:
            w.writerow({k: ', '.join(v) if isinstance(v, list) else v for k, v in row.items() if k in w.fieldnames})
    with open(job_report / 'flows.csv', 'w', newline='') as f:
        rows = result.get('flows', [])
        w = csv.DictWriter(f, fieldnames=['src_ip','dst_ip','protocol','dport','packets','bytes','first_seen','last_seen'])
        w.writeheader()
        for row in rows:
            w.writerow({k: row.get(k, '') for k in w.fieldnames})
    with open(job_report / 'normalized_events.csv', 'w', newline='') as f:
        fields = ['timestamp','platform','log_source','event_type','host','user','process','src_ip','dst_ip','attack_candidates','confidence','raw']
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader()
        for e in evs:
            row = dict(e); row['attack_candidates'] = ', '.join(e.get('attack_candidates') or [])
            w.writerow({k: row.get(k, '') for k in fields})

    navigator_validation = {}
    if ctx:
        observed_layer = strict_navigator_layer(ctx)
    else:
        class SavedContext: pass
        saved = SavedContext(); saved.techniques = {}
        for t in result.get('techniques', []):
            tid = t.get('techniqueID') or t.get('technique_id')
            if tid: saved.techniques[tid] = dict(t)
        observed_layer = strict_navigator_layer(saved)
    validate_layer(observed_layer)
    write_json(job_export / 'mitre_navigator_layer.json', observed_layer)
    navigator_validation['mitre_navigator_layer.json'] = {'navigator_import': True, 'layer_version': observed_layer.get('versions', {}).get('layer'), 'techniques': len(observed_layer.get('techniques', [])), 'purpose': 'Observed ATT&CK Navigator layer'}

    theoretical_layer = strict_data_source_coverage_layer(result, name='Theoretical ATT&CK Coverage')
    validate_layer(theoretical_layer)
    write_json(job_export / 'mitre_data_source_coverage_layer.json', theoretical_layer)
    navigator_validation['mitre_data_source_coverage_layer.json'] = {'navigator_import': True, 'layer_version': theoretical_layer.get('versions', {}).get('layer'), 'techniques': len(theoretical_layer.get('techniques', [])), 'purpose': 'Theoretical/data-source ATT&CK Navigator layer only'}

    unified_layer = strict_unified_coverage_layer(result, name='Unified ATT&CK Coverage')
    validate_layer(unified_layer)
    write_json(job_export / 'mitre_unified_coverage_layer.json', unified_layer)
    navigator_validation['mitre_unified_coverage_layer.json'] = {'navigator_import': True, 'layer_version': unified_layer.get('versions', {}).get('layer'), 'techniques': len(unified_layer.get('techniques', [])), 'purpose': 'Unified observed/theoretical/detectable/validated ATT&CK Navigator layer'}
    navigator_validation['enterprise_attack_coverage_model.json'] = {'navigator_import': False, 'purpose': 'PCAP Mapper application coverage model JSON; do not import into Navigator'}
    navigator_validation['enterprise_attack_coverage.json'] = {'navigator_import': False, 'purpose': 'PCAP Mapper enterprise coverage assessment JSON; do not import into Navigator'}
    write_json(job_report / 'mitre_data_source_coverage.json', coverage)
    write_json(job_report / 'enterprise_attack_coverage.json', enterprise)
    write_json(job_report / 'enterprise_attack_coverage_model.json', coverage_model)
    write_json(job_report / 'rule_validation_results.json', validations)
    write_json(job_report / 'attack_v18_rule_coverage_report.json', attack_coverage_report(load_rules(include_disabled=True)))
    write_json(job_report / 'event_diagnostics.json', {'summary': summary, 'mapped_events': [e for e in evs if e.get('attack_candidates')], 'unmapped_events': [e for e in evs if not e.get('attack_candidates')][:1000]})
    write_json(job_report / 'potential_attack_coverage.json', potential)
    _write_potential_coverage_reports(job_report, potential)

    with open(job_export / 'elastic_bulk.ndjson', 'w') as f:
        for section in ['hosts','flows','findings','log_sources','techniques','normalized_events']:
            for doc in result.get(section, []):
                f.write(json.dumps({'index': {'_index': f'pcap-{section}'}}) + '\n')
                f.write(json.dumps(doc, default=str) + '\n')
    return {'report_dir': str(job_report), 'export_dir': str(job_export)}
