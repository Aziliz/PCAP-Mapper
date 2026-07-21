from pathlib import Path
p=Path('/mnt/data/stix_choice/app/attack/versioned.py')
text=p.read_text()
append=r'''

# ---------------------------------------------------------------------------
# Coverage engine selection and STIX-driven applicability/telemetry expansion.
# This block intentionally appears at the end of the module so it overrides the
# older heuristic definitions above while keeping them available as the optional
# legacy/heuristic engine.
# ---------------------------------------------------------------------------
_HEURISTIC_BUILD_DATA_SOURCE_COVERAGE = build_data_source_coverage

COVERAGE_ENGINE_STIX = 'stix'
COVERAGE_ENGINE_HEURISTIC = 'heuristic'
VALID_COVERAGE_ENGINES = {COVERAGE_ENGINE_STIX, COVERAGE_ENGINE_HEURISTIC}


def coverage_engine_from_result(result=None, coverage_engine=None):
    raw = coverage_engine
    if raw is None and isinstance(result, dict):
        raw = result.get('coverage_engine') or result.get('coverage_engine_mode') or result.get('coverage_model_engine')
    if raw is None:
        import os
        raw = os.getenv('PCAP_MAPPER_COVERAGE_ENGINE') or os.getenv('ATTACK_COVERAGE_ENGINE') or COVERAGE_ENGINE_STIX
    raw = str(raw or COVERAGE_ENGINE_STIX).strip().lower().replace('_', '-').replace(' ', '-')
    if raw in {'stix-driven', 'stix-v18', 'official-stix', 'official'}:
        raw = COVERAGE_ENGINE_STIX
    if raw in {'legacy-heuristic', 'legacy', 'old'}:
        raw = COVERAGE_ENGINE_HEURISTIC
    return raw if raw in VALID_COVERAGE_ENGINES else COVERAGE_ENGINE_STIX


def _norm_attack_string(value):
    return ' '.join(str(value or '').replace('_', ' ').replace('-', ' ').replace('/', ' ').replace(':', ' ').lower().split())


def _split_attack_data_source(value):
    value = str(value or '').strip()
    if ':' in value:
        ds, comp = value.split(':', 1)
        return ds.strip(), comp.strip()
    return value, ''


def _stix_component_catalog():
    comps = {}
    data_sources = {}
    for tid, meta in VALID_TECHNIQUES.items():
        for entry in meta.get('data_sources', []) or []:
            ds, comp = _split_attack_data_source(entry)
            if ds:
                data_sources.setdefault(_norm_attack_string(ds), {'name': ds, 'techniques': set()})['techniques'].add(tid)
            if comp:
                comps.setdefault(_norm_attack_string(comp), {'name': comp, 'data_source': ds, 'techniques': set()})['techniques'].add(tid)
    return comps, data_sources


def _detected_scope_to_stix_platforms(scope):
    scope = {_norm_attack_string(x) for x in (scope or [])}
    out = set()
    if 'windows' in scope:
        out.update({'windows'})
    if 'linux' in scope:
        out.update({'linux'})
    if 'macos' in scope or 'mac os' in scope:
        out.update({'macos', 'macos'})
    if 'network' in scope:
        out.update({'network', 'network device'})
    if 'cloud' in scope:
        out.update({'iaas', 'saas', 'office suite', 'identity provider', 'containers'})
    # Enterprise/network telemetry can often observe multi-platform traffic.
    if 'network' in scope:
        out.update({'windows', 'linux', 'macos'})
    return out


def _platform_to_scope_token(platform):
    p = _norm_attack_string(platform)
    if p in {'macos', 'mac os'}:
        return 'macos'
    if p in {'network device', 'network devices', 'network'}:
        return 'network device'
    return p


def _stix_technique_in_detected_scope(tid, meta, scope):
    """Applicability using STIX x_mitre_platforms only, not technique names."""
    platforms = {_platform_to_scope_token(p) for p in (meta.get('platforms') or []) if p}
    if not platforms:
        return True
    detected = _detected_scope_to_stix_platforms(scope)
    if not detected:
        return True
    if platforms & detected:
        return True
    # ATT&CK's PRE/external tactics are modeled separately from environment scope.
    if _is_external_visibility_tactic(meta.get('tactic', '')):
        return False
    return False


def _source_stix_matches(source):
    """Return ATT&CK data components/sources/techniques supported by a log source.

    This uses the official STIX x_mitre_data_sources strings from each technique
    and the app's parser/source inventory only to translate detected log names
    into canonical ATT&CK data component names. It does not use technique-name or
    tactic-name heuristics.
    """
    source = _canon_source_name(source) or source
    catalog_components, catalog_sources = _stix_component_catalog()
    configured_components = SOURCE_COMPONENTS.get(source, []) or []
    matched_components = {}
    matched_sources = {}
    techniques = set()

    for raw_comp in configured_components:
        raw = str(raw_comp or '').replace('Log Source:', '').strip()
        ds_hint, comp_hint = _split_attack_data_source(raw)
        candidates = []
        if comp_hint:
            candidates.append(comp_hint)
        candidates.append(raw)
        candidates.append(ds_hint)
        for cand in candidates:
            key = _norm_attack_string(cand)
            if not key:
                continue
            # Exact component/data-source matches first.
            if key in catalog_components:
                rec = catalog_components[key]
                matched_components[rec['name']] = rec
                techniques.update(rec['techniques'])
            if key in catalog_sources:
                rec = catalog_sources[key]
                matched_sources[rec['name']] = rec
                techniques.update(rec['techniques'])
            # Conservative substring match for app-specific phrases like
            # "Network Traffic Flow", "PowerShell Script Block", etc.
            for ckey, rec in catalog_components.items():
                if key and (key == ckey or key in ckey or ckey in key):
                    matched_components[rec['name']] = rec
                    techniques.update(rec['techniques'])
            for skey, rec in catalog_sources.items():
                if key and (key == skey or key in skey or skey in key):
                    matched_sources[rec['name']] = rec
                    techniques.update(rec['techniques'])

    # If the detected source itself is a canonical ATT&CK data source name, use it.
    source_key = _norm_attack_string(source)
    for skey, rec in catalog_sources.items():
        if source_key == skey or source_key in skey or skey in source_key:
            matched_sources[rec['name']] = rec
            techniques.update(rec['techniques'])

    # Derive data-source names from matched components where STIX supplied one.
    for rec in list(matched_components.values()):
        ds = rec.get('data_source')
        if ds:
            matched_sources.setdefault(ds, {'name': ds, 'techniques': set()})

    return {
        'source': source,
        'data_components': sorted(matched_components),
        'attack_data_sources': sorted(matched_sources),
        'techniques': {tid for tid in techniques if tid in VALID_TECHNIQUES},
    }


def build_data_source_coverage(result, coverage_engine=None):
    engine = coverage_engine_from_result(result, coverage_engine)
    if engine == COVERAGE_ENGINE_HEURISTIC:
        return _HEURISTIC_BUILD_DATA_SOURCE_COVERAGE(result)

    coverage = {}
    for source in detected_data_sources(result or {}):
        source = _canon_source_name(source) or source
        category = SOURCE_CATEGORY.get(source, 'Other')
        match = _source_stix_matches(source)
        components = set(match.get('data_components') or [])
        attack_data_sources = set(match.get('attack_data_sources') or [])
        for tid in match.get('techniques') or []:
            meta = VALID_TECHNIQUES.get(tid)
            if not meta:
                continue
            score = 82
            if source in {'Sysmon', 'Defender for Endpoint', 'Windows Security', 'auditd', 'osquery', 'Zeek', 'Suricata'}:
                score = 90
            elif category in {'Windows', 'Linux', 'macOS'}:
                score = 80
            elif category == 'Network':
                score = 74
            cur = coverage.setdefault(tid, {
                'techniqueID': tid,
                'name': meta.get('name', tid),
                'tactic': meta.get('tactic', ''),
                'score': 0,
                'coverage': 'Theoretical',
                'data_sources': set(),
                'data_components': set(),
                'attack_data_sources': set(),
                'rationale': [],
                'coverage_engine': COVERAGE_ENGINE_STIX,
            })
            cur['score'] = max(cur['score'], score)
            cur['data_sources'].add(source)
            cur['data_components'].update(components)
            cur['attack_data_sources'].update(attack_data_sources)
            cur['rationale'].append(
                f"{source} detected -> STIX x_mitre_data_sources match ({len(components)} components, {len(attack_data_sources)} data sources) -> supports {meta.get('name', tid)} theoretically."
            )
    out = []
    for item in coverage.values():
        for key in ('data_sources', 'data_components', 'attack_data_sources'):
            item[key] = sorted(item[key])
        item['rationale'] = item['rationale'][:8]
        out.append(item)
    return sorted(out, key=lambda x: (-x['score'], x['tactic'], x['techniqueID']))


def _build_model_with_engine(result, rules=None, coverage_engine=None):
    result = result or {}
    rules = rules or []
    engine = coverage_engine_from_result(result, coverage_engine)
    data_source_items = result.get('data_source_coverage')
    if not data_source_items or result.get('coverage_engine') != engine:
        data_source_items = build_data_source_coverage({**result, 'coverage_engine': engine}, engine)
    data_source_by_id = {x.get('techniqueID'): x for x in data_source_items if x.get('techniqueID') in VALID_TECHNIQUES}
    observed_raw = _attack_id_set_from_result(result)
    validated_raw, validated_details = _validated_ids_and_details(result)
    detected_sources = detected_data_sources(result)
    coverage_scope = _detected_coverage_scope(result, detected_sources)
    if engine == COVERAGE_ENGINE_HEURISTIC:
        applicable_ids = {tid for tid, meta in VALID_TECHNIQUES.items() if _technique_in_detected_scope(tid, meta, coverage_scope) and not _is_external_visibility_tactic(meta.get('tactic', ''))}
        basis = 'environment-scoped ATT&CK coverage model using legacy heuristic applicability'
    else:
        applicable_ids = {tid for tid, meta in VALID_TECHNIQUES.items() if _stix_technique_in_detected_scope(tid, meta, coverage_scope) and not _is_external_visibility_tactic(meta.get('tactic', ''))}
        basis = 'environment-scoped ATT&CK coverage model using STIX platforms and x_mitre_data_sources'
    external_visibility_ids = {tid for tid, meta in VALID_TECHNIQUES.items() if _is_external_visibility_tactic(meta.get('tactic', ''))}
    theoretical_ids = set(data_source_by_id) & applicable_ids
    observed_ids = observed_raw & applicable_ids
    validated_ids = validated_raw & applicable_ids
    rule_names_by_tid = _supporting_rules_by_tid(rules)
    rule_techs = set(rule_names_by_tid)

    techniques = []
    tactic_totals = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_observed = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_theoretical = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_validated = {t: 0 for t in TACTIC_DISPLAY_ORDER}
    tactic_strength_sum = {t: 0.0 for t in TACTIC_DISPLAY_ORDER}

    for tid, meta in sorted(VALID_TECHNIQUES.items()):
        tactic = meta.get('tactic', '')
        external_visibility = _is_external_visibility_tactic(tactic)
        external_visibility_reason = _external_visibility_reason(tactic)
        applicable = (tid in applicable_ids) and not external_visibility
        ds = data_source_by_id.get(tid, {})
        score = float(ds.get('score', 0) or 0)
        obs = tid in observed_ids
        theo = tid in theoretical_ids
        val = tid in validated_ids
        detectable = applicable and (tid in rule_techs)
        if val and score < 90:
            score = 90.0
        elif obs and score < 70:
            score = 70.0
        if external_visibility:
            state, score = 'External Visibility', 0.0
        elif not applicable:
            state, score = 'Not Applicable', 0.0
        elif obs:
            state = 'Observed + Theoretical' if theo else 'Observed'
        elif val:
            state = 'Validated'
        elif theo and detectable:
            state = 'Theoretical + Detectable'
        elif theo:
            state = 'Theoretical'
        elif detectable:
            state = 'Detectable'
        else:
            state = 'Not Covered'
        if applicable:
            if tactic not in tactic_totals:
                tactic_totals[tactic] = tactic_observed[tactic] = tactic_theoretical[tactic] = tactic_validated[tactic] = 0
                tactic_strength_sum[tactic] = 0.0
            tactic_totals[tactic] += 1
            if obs:
                tactic_observed[tactic] += 1
            if theo:
                tactic_theoretical[tactic] += 1
                tactic_strength_sum[tactic] += score
            if val:
                tactic_validated[tactic] += 1
        evidence = []
        evidence.extend(ds.get('rationale', []) or [])
        evidence.extend((validated_details.get(tid, {}) or {}).get('evidence', []) or [])
        techniques.append({
            'techniqueID': tid, 'technique_id': tid, 'name': meta.get('name', tid), 'tactic': tactic,
            'applicable': applicable, 'observed': obs, 'theoretical': theo, 'detectable': detectable,
            'validated': val, 'validated_raw': tid in validated_raw, 'observed_raw': tid in observed_raw,
            'out_of_scope_validated_match': (tid in validated_raw) and not applicable,
            'out_of_scope_observed_match': (tid in observed_raw) and not applicable,
            'external_visibility': external_visibility, 'external_visibility_reason': external_visibility_reason,
            'not_applicable': (not applicable) and not external_visibility, 'state': state,
            'state_class': _coverage_state_class({'applicable': applicable, 'external_visibility': external_visibility, 'observed': obs, 'theoretical': theo, 'validated': val, 'rule': detectable, 'score': score}),
            'score': round(score, 1), 'confidence': round(score, 1), 'rule': detectable,
            'supporting_rules': sorted(rule_names_by_tid.get(tid, [])),
            'data_sources': sorted(ds.get('data_sources', []) or []),
            'data_components': sorted(ds.get('data_components', []) or []),
            'attack_data_sources': sorted(ds.get('attack_data_sources', []) or []),
            'stix_platforms': meta.get('platforms', []) or [],
            'stix_data_sources': meta.get('data_sources', []) or [],
            'coverage_engine': engine,
            'evidence': evidence[:12], 'rationale': (ds.get('rationale', []) or [])[:8],
            'validated_rules': (validated_details.get(tid, {}) or {}).get('rules', []),
            'validated_evidence': (validated_details.get(tid, {}) or {}).get('evidence', []),
            'match_count': (validated_details.get(tid, {}) or {}).get('match_count', 0),
        })

    def rollup(kind):
        out = []
        for tac in TACTIC_DISPLAY_ORDER:
            total = tactic_totals.get(tac, 0)
            if kind == 'observed':
                covered, strength = tactic_observed.get(tac, 0), 100 if tactic_observed.get(tac, 0) else 0
            elif kind == 'validated':
                covered, strength = tactic_validated.get(tac, 0), 100 if tactic_validated.get(tac, 0) else 0
            else:
                covered = tactic_theoretical.get(tac, 0)
                strength = tactic_strength_sum.get(tac, 0.0) / covered if covered else 0
            pct = round((covered / total) * 100, 1) if total else 0
            score = pct if kind != 'theoretical' else (round((pct * 0.65) + (strength * 0.35), 1) if total else 0)
            out.append({'tactic': tac, 'name': _tactic_name(tac), 'covered': covered, 'total': total, 'not_applicable': len([x for x in techniques if x.get('tactic') == tac and not x.get('applicable') and not x.get('external_visibility')]), 'external_visibility': len([x for x in techniques if x.get('tactic') == tac and x.get('external_visibility')]), 'coverage_pct': pct, 'avg_strength': round(strength, 1), 'score': round(score, 1)})
        return out

    applicable_total = len(applicable_ids)
    theoretical_count = len(theoretical_ids)
    avg_strength = sum(t['score'] for t in techniques if t['theoretical']) / theoretical_count if theoretical_count else 0
    breadth = theoretical_count / applicable_total * 100 if applicable_total else 0
    overall = round((breadth * 0.65) + (avg_strength * 0.35), 1) if applicable_total else 0
    return {
        'basis': basis,
        'coverage_engine': engine,
        'attack_version': ATTACK_VERSION, 'navigator_version': NAVIGATOR_VERSION,
        'dataset_label': ATTACK_DATASET_METADATA.get('dataset_label', 'ATT&CK Enterprise v18 STIX'),
        'dataset_source': ATTACK_DATASET_METADATA.get('source'), 'coverage_scope': coverage_scope,
        'detected_log_sources': detected_sources,
        'scoped_technique_total': applicable_total, 'total_registry_techniques': len(VALID_TECHNIQUES),
        'not_applicable_count': len(VALID_TECHNIQUES) - applicable_total - len(external_visibility_ids),
        'external_visibility_count': len(external_visibility_ids),
        'external_visibility_ids': sorted(external_visibility_ids),
        'observed_count': len(observed_ids), 'theoretical_count': theoretical_count,
        'validated_count': len(validated_ids), 'detectable_count': len([tid for tid in applicable_ids if tid in rule_techs]),
        'out_of_scope_validated_count': len([tid for tid in validated_raw if tid not in applicable_ids]),
        'out_of_scope_observed_count': len([tid for tid in observed_raw if tid not in applicable_ids]),
        'observed_score': round((len(observed_ids) / applicable_total) * 100, 1) if applicable_total else 0,
        'theoretical_score': overall, 'validated_score': round((len(validated_ids) / applicable_total) * 100, 1) if applicable_total else 0,
        'overall_score': overall, 'maturity': 'High' if overall >= 75 else 'Moderate' if overall >= 55 else 'Basic' if overall >= 30 else 'Limited',
        'techniques': techniques,
        'rollups': {'observed': rollup('observed'), 'theoretical': rollup('theoretical'), 'validated': rollup('validated')},
        'observed_ids': sorted(observed_ids), 'theoretical_ids': sorted(theoretical_ids), 'validated_ids': sorted(validated_ids),
        'detectable_ids': sorted([tid for tid in applicable_ids if tid in rule_techs]), 'applicable_ids': sorted(applicable_ids),
    }


def build_enterprise_attack_coverage_model(result, rules=None, coverage_engine=None):
    return _build_model_with_engine(result, rules, coverage_engine)


def theoretical_coverage_diagnostics(result, coverage_engine=None):
    result = result or {}
    engine = coverage_engine_from_result(result, coverage_engine)
    detected_sources = detected_data_sources(result)
    scope = _detected_coverage_scope(result, detected_sources)
    coverage = build_data_source_coverage({**result, 'coverage_engine': engine}, engine)
    if engine == COVERAGE_ENGINE_HEURISTIC:
        applicable_ids = {tid for tid, meta in VALID_TECHNIQUES.items() if _technique_in_detected_scope(tid, meta, scope) and not _is_external_visibility_tactic(meta.get('tactic', ''))}
    else:
        applicable_ids = {tid for tid, meta in VALID_TECHNIQUES.items() if _stix_technique_in_detected_scope(tid, meta, scope) and not _is_external_visibility_tactic(meta.get('tactic', ''))}
    theoretical_ids = {x.get('techniqueID') for x in coverage if x.get('techniqueID') in applicable_ids}
    component_map = {}
    attack_ds = {}
    source_rows = []
    for source in detected_sources:
        if engine == COVERAGE_ENGINE_HEURISTIC:
            comps = SOURCE_COMPONENTS.get(source, []) or []
            tids = set(_source_technique_expansion(source)) & applicable_ids
            ds_names = _attck_data_sources_for_source(source)
        else:
            match = _source_stix_matches(source)
            comps = match.get('data_components') or []
            tids = set(match.get('techniques') or []) & applicable_ids
            ds_names = match.get('attack_data_sources') or []
        for comp in comps:
            component_map.setdefault(comp, set()).add(source)
        for ds in ds_names:
            attack_ds.setdefault(ds, set()).add(source)
        source_rows.append({'source': source, 'category': SOURCE_CATEGORY.get(source, 'Other'), 'components': comps, 'attack_data_sources': ds_names, 'technique_count': len(tids), 'sample_techniques': sorted(tids)[:16]})
    unmapped = []
    for row in source_rows:
        if not row['components'] or row['technique_count'] == 0:
            src = row['source']; cat = row['category']
            suggested = 'Add or tune a parser that emits normalized_events[].log_source with canonical source names.'
            suggested_comp = 'Process: Process Creation' if cat in ('Windows', 'Linux', 'macOS') else 'Network Traffic: Network Traffic Flow'
            unmapped.append({'source': src, 'reason': 'No STIX data component/source mapping found.' if engine == COVERAGE_ENGINE_STIX and not row['components'] else 'Components did not resolve to in-scope ATT&CK techniques.', 'suggested_parser': suggested, 'suggested_attack_data_component': suggested_comp})
    return {
        'coverage_engine': engine,
        'detected_os_scope': scope,
        'detected_operating_systems': [s.replace('windows', 'Windows').replace('linux', 'Linux').replace('macos', 'macOS').replace('network', 'Network').replace('cloud', 'Cloud') for s in scope],
        'detected_log_sources': detected_sources,
        'source_rows': sorted(source_rows, key=lambda r: (r['category'], r['source'])),
        'components': [{'component': c, 'sources': sorted(s)} for c, s in sorted(component_map.items())],
        'attack_data_sources': [{'data_source': c, 'sources': sorted(s)} for c, s in sorted(attack_ds.items())],
        'supported_techniques': sorted(theoretical_ids),
        'supported_technique_count': len(theoretical_ids),
        'applicable_technique_count': len(applicable_ids),
        'theoretical_technique_count': len(theoretical_ids),
        'coverage_ratio': f"{len(theoretical_ids)} / {len(applicable_ids)}" if applicable_ids else '0 / 0',
        'unmapped_sources': [u['source'] for u in unmapped],
        'unmapped_details': unmapped,
        'pipeline': ['Detected Log Source', 'ATT&CK Data Components', 'ATT&CK Data Sources', 'Supported ATT&CK Techniques', 'Unified Coverage Model', 'Heat Maps / Reports / Navigator'],
    }


def enterprise_coverage_assessment(result, rules=None, coverage_engine=None):
    result = result or {}
    rules = rules or []
    engine = coverage_engine_from_result(result, coverage_engine)
    model = build_enterprise_attack_coverage_model({**result, 'coverage_engine': engine}, rules, engine)
    diag = theoretical_coverage_diagnostics({**result, 'coverage_engine': engine}, engine)
    enterprise = {
        'basis': model['basis'], 'coverage_engine': engine,
        'attack_version': model['attack_version'], 'navigator_version': model['navigator_version'],
        'dataset_label': model.get('dataset_label'), 'dataset_source': model.get('dataset_source'),
        'overall_score': model['overall_score'], 'observed_score': model['observed_score'], 'theoretical_score': model['theoretical_score'], 'validated_score': model['validated_score'],
        'maturity': model['maturity'], 'detected_sources': diag['detected_log_sources'], 'coverage_scope': model['coverage_scope'],
        'scoped_technique_total': model['scoped_technique_total'], 'total_registry_techniques': model['total_registry_techniques'], 'not_applicable_count': model['not_applicable_count'],
        'external_visibility_count': model.get('external_visibility_count', 0),
        'observed_count': model['observed_count'], 'theoretical_count': model['theoretical_count'], 'validated_count': model['validated_count'], 'detectable_count': model['detectable_count'],
        'out_of_scope_validated_count': model.get('out_of_scope_validated_count', 0), 'out_of_scope_observed_count': model.get('out_of_scope_observed_count', 0),
        'telemetry_inventory': {}, 'data_components': diag['components'], 'attack_data_sources': diag['attack_data_sources'],
        'tactic_coverage': model['rollups']['theoretical'], 'tactic_rollups': model['rollups'], 'coverage_states': model['techniques'],
        'theoretical_diagnostics': diag, 'gaps': [], 'recommendations': [], 'rule_coverage': {}, 'readiness': [], 'executive_summary': '',
    }
    grouped = {}
    for source in diag['detected_log_sources']:
        grouped.setdefault(SOURCE_CATEGORY.get(source, 'Other'), []).append(source)
    for cat in sorted(set(list(grouped) + ['Windows', 'Linux', 'macOS', 'Network', 'Cloud', 'SIEM / Forwarding'])):
        enterprise['telemetry_inventory'][cat] = sorted(grouped.get(cat, []))
    for tc in enterprise['tactic_coverage']:
        if tc['total'] and tc['score'] < 50:
            enterprise['gaps'].append({'tactic': tc['name'], 'coverage': tc['score'], 'gap': 'Low theoretical telemetry coverage for this tactic.'})
        elif tc['total'] and tc['score'] < 70:
            enterprise['gaps'].append({'tactic': tc['name'], 'coverage': tc['score'], 'gap': 'Partial theoretical telemetry coverage; validate data components and rules.'})
        enterprise['readiness'].append({'tactic': tc['name'], 'readiness': 'Excellent' if tc['score'] >= 80 else 'Good' if tc['score'] >= 65 else 'Fair' if tc['score'] >= 45 else 'Poor', 'score': tc['score']})
    rule_techs = _rule_technique_ids(rules)
    enterprise['rule_coverage'] = {
        'techniques_with_rules': len(rule_techs),
        'applicable_techniques_with_rules': len([tid for tid in rule_techs if tid in model['applicable_ids']]),
        'detectable_techniques': model['detectable_count'],
        'covered_with_rules': len([tid for tid in rule_techs if tid in model['theoretical_ids']]),
        'applicable_without_rules': len([tid for tid in model['applicable_ids'] if tid not in rule_techs]),
        'validated_techniques': model['validated_count'],
    }
    enterprise['recommendations'] = [r for r in RECOMMENDATION_LIBRARY if r.get('source') not in diag['detected_log_sources']][:8]
    enterprise['executive_summary'] = (
        f"Scoped enterprise ATT&CK coverage is {model['overall_score']}% across {model['scoped_technique_total']} applicable techniques. "
        f"Engine: {'STIX-driven' if engine == COVERAGE_ENGINE_STIX else 'heuristic'}. "
        f"Observed: {model['observed_count']}; theoretical: {model['theoretical_count']}; detectable: {model['detectable_count']}; validated: {model['validated_count']}. "
        f"Detected log sources: {', '.join(diag['detected_log_sources']) if diag['detected_log_sources'] else 'none'}."
    )
    return enterprise
'''
p.write_text(text+append)

# Patch coverage cache to include engine and use selected/default engine.
p=Path('/mnt/data/stix_choice/app/coverage_cache.py')
text=p.read_text()
text=text.replace('COVERAGE_CACHE_VERSION = \'pcap-mapper-v2-coverage-cache-2026-07-09-2\'', "COVERAGE_CACHE_VERSION = 'pcap-mapper-v2-coverage-cache-2026-07-09-3-stix-engine'")
text=text.replace('    build_enterprise_attack_coverage_model,\n)', '    build_enterprise_attack_coverage_model,\n    coverage_engine_from_result,\n)')
text=text.replace("        'rule_validation_status': result.get('rule_validation_status'),\n    }", "        'rule_validation_status': result.get('rule_validation_status'),\n        'coverage_engine': coverage_engine_from_result(result),\n    }")
text=text.replace("        and meta.get('rules_signature') == rules_signature(rules)\n        and _has_cached_model(result)", "        and meta.get('rules_signature') == rules_signature(rules)\n        and meta.get('coverage_engine') == coverage_engine_from_result(result)\n        and _has_cached_model(result)")
text=text.replace("        and meta.get('version') == COVERAGE_CACHE_VERSION\n        and not meta.get('stale')\n        and _has_cached_model(result)", "        and meta.get('version') == COVERAGE_CACHE_VERSION\n        and not meta.get('stale')\n        and meta.get('coverage_engine') == coverage_engine_from_result(result)\n        and _has_cached_model(result)")
text=text.replace("    coverage = build_data_source_coverage(result)\n    result['data_source_coverage'] = coverage\n    enterprise = enterprise_coverage_assessment(result, rules)\n    result['enterprise_coverage'] = enterprise\n    model = build_enterprise_attack_coverage_model(result, rules)", "    engine = coverage_engine_from_result(result)\n    result['coverage_engine'] = engine\n    coverage = build_data_source_coverage(result, engine)\n    result['data_source_coverage'] = coverage\n    enterprise = enterprise_coverage_assessment(result, rules, engine)\n    result['enterprise_coverage'] = enterprise\n    model = build_enterprise_attack_coverage_model(result, rules, engine)")
text=text.replace("        'input_signature': input_sig,\n        'rules_signature': rules_sig,", "        'input_signature': input_sig,\n        'rules_signature': rules_sig,\n        'coverage_engine': engine,")
p.write_text(text)

# Patch web import and context choice.
p=Path('/mnt/data/stix_choice/app/web.py')
text=p.read_text()
text=text.replace('    _technique_in_detected_scope,\n)', '    _technique_in_detected_scope,\n    coverage_engine_from_result,\n)')
old="""def build_mitre_page_context(job_arg=None, attack_mode_arg=None):\n    \"\"\"Shared MITRE page context for Coverage, Data Sources, and Normalized Events pages.\"\"\"\n    result, jid = load_result(job_arg)\n    attack_mode = (attack_mode_arg or 'stix').lower()\n    if attack_mode not in ('stix', 'legacy'):\n        attack_mode = 'stix'\n    rules = None\n    if attack_mode == 'legacy':\n        # Legacy mode is explicitly comparative and may need its older transform.\n        rules = load_rules()\n        result['data_source_coverage'] = result.get('data_source_coverage') or build_data_source_coverage(result)\n        result = build_legacy_heatmap_display(result, rules)\n    else:\n        result, rebuilt = ensure_coverage_cache(result)\n        if rebuilt and jid:\n            save_result_for_job(jid, result)\n    tactic_rollups = build_tactic_rollups(result, rules, attack_mode=attack_mode)\n    return result, jid, attack_mode, tactic_rollups\n"""
new="""def build_mitre_page_context(job_arg=None, attack_mode_arg=None, coverage_engine_arg=None):\n    \"\"\"Shared MITRE page context for Coverage, Data Sources, and Normalized Events pages.\"\"\"\n    result, jid = load_result(job_arg)\n    attack_mode = (attack_mode_arg or 'stix').lower()\n    if attack_mode not in ('stix', 'legacy'):\n        attack_mode = 'stix'\n    coverage_engine = coverage_engine_from_result(result, coverage_engine_arg)\n    result['coverage_engine'] = coverage_engine\n    rules = None\n    if attack_mode == 'legacy':\n        # Legacy mode is explicitly comparative and may need its older transform.\n        rules = load_rules()\n        result['data_source_coverage'] = result.get('data_source_coverage') or build_data_source_coverage(result, coverage_engine)\n        result = build_legacy_heatmap_display(result, rules)\n    else:\n        result, rebuilt = ensure_coverage_cache(result)\n        if rebuilt and jid:\n            save_result_for_job(jid, result)\n    tactic_rollups = build_tactic_rollups(result, rules, attack_mode=attack_mode)\n    return result, jid, attack_mode, tactic_rollups, coverage_engine\n"""
if old not in text:
    raise SystemExit('web context block not found')
text=text.replace(old,new)
text=text.replace("result, jid, attack_mode, tactic_rollups = build_mitre_page_context(request.args.get('job'), request.args.get('attack_mode'))\n    return render_template('mitre.html', result=result, job_id=jid, tactic_rollups=tactic_rollups, attack_mode=attack_mode)", "result, jid, attack_mode, tactic_rollups, coverage_engine = build_mitre_page_context(request.args.get('job'), request.args.get('attack_mode'), request.args.get('coverage_engine'))\n    return render_template('mitre.html', result=result, job_id=jid, tactic_rollups=tactic_rollups, attack_mode=attack_mode, coverage_engine=coverage_engine)")
text=text.replace("result, jid, attack_mode, tactic_rollups = build_mitre_page_context(request.args.get('job'), request.args.get('attack_mode'))\n    return render_template('mitre_data_sources.html', result=result, job_id=jid, tactic_rollups=tactic_rollups, attack_mode=attack_mode)", "result, jid, attack_mode, tactic_rollups, coverage_engine = build_mitre_page_context(request.args.get('job'), request.args.get('attack_mode'), request.args.get('coverage_engine'))\n    return render_template('mitre_data_sources.html', result=result, job_id=jid, tactic_rollups=tactic_rollups, attack_mode=attack_mode, coverage_engine=coverage_engine)")
text=text.replace("result, jid, attack_mode, tactic_rollups = build_mitre_page_context(request.args.get('job'), request.args.get('attack_mode'))\n    return render_template('mitre_normalized_events.html', result=result, job_id=jid, tactic_rollups=tactic_rollups, attack_mode=attack_mode)", "result, jid, attack_mode, tactic_rollups, coverage_engine = build_mitre_page_context(request.args.get('job'), request.args.get('attack_mode'), request.args.get('coverage_engine'))\n    return render_template('mitre_normalized_events.html', result=result, job_id=jid, tactic_rollups=tactic_rollups, attack_mode=attack_mode, coverage_engine=coverage_engine)")
# Patch validate hidden field maybe preserves coverage_engine
text=text.replace("request.form.get('attack_mode') or request.args.get('attack_mode') or 'stix'", "request.form.get('attack_mode') or request.args.get('attack_mode') or 'stix'")
p.write_text(text)

# Patch mitre template form.
p=Path('/mnt/data/stix_choice/app/templates/mitre.html')
text=p.read_text()
old="""    <label>ATT&CK processing mode\n      <select name=\"attack_mode\">\n        <option value=\"stix\" {% if attack_mode != 'legacy' %}selected{% endif %}>Official ATT&CK v18 STIX</option>\n        <option value=\"legacy\" {% if attack_mode == 'legacy' %}selected{% endif %}>Legacy processing</option>\n      </select>\n    </label>\n    <button class=\"btn\" type=\"submit\">Apply</button>\n    <span class=\"muted\">{{ 'Using legacy bundled registry/rollups.' if attack_mode == 'legacy' else 'Using bundled ATT&CK Enterprise v18 STIX dataset.' }}</span>\n"""
new="""    <label>ATT&CK processing mode\n      <select name=\"attack_mode\">\n        <option value=\"stix\" {% if attack_mode != 'legacy' %}selected{% endif %}>Official ATT&CK v18 STIX</option>\n        <option value=\"legacy\" {% if attack_mode == 'legacy' %}selected{% endif %}>Legacy processing</option>\n      </select>\n    </label>\n    <label>Coverage engine\n      <select name=\"coverage_engine\">\n        <option value=\"stix\" {% if coverage_engine != 'heuristic' %}selected{% endif %}>STIX-driven applicability/data sources (default)</option>\n        <option value=\"heuristic\" {% if coverage_engine == 'heuristic' %}selected{% endif %}>Legacy heuristic applicability/data sources</option>\n      </select>\n    </label>\n    <button class=\"btn\" type=\"submit\">Apply</button>\n    <span class=\"muted\">{{ 'Using legacy bundled registry/rollups.' if attack_mode == 'legacy' else ('Using STIX-driven coverage engine.' if coverage_engine != 'heuristic' else 'Using legacy heuristic coverage engine.') }}</span>\n"""
text=text.replace(old,new)
text=text.replace("<input type=\"hidden\" name=\"job\" value=\"{{ job_id or '' }}\"><input type=\"hidden\" name=\"attack_mode\" value=\"{{ attack_mode or 'stix' }}\"><button", "<input type=\"hidden\" name=\"job\" value=\"{{ job_id or '' }}\"><input type=\"hidden\" name=\"attack_mode\" value=\"{{ attack_mode or 'stix' }}\"><input type=\"hidden\" name=\"coverage_engine\" value=\"{{ coverage_engine or 'stix' }}\"><button")
text=text.replace("<b>Dataset:</b> {{ ec.get('dataset_label', 'ATT&CK Enterprise v18 STIX') }}", "<b>Dataset:</b> {{ ec.get('dataset_label', 'ATT&CK Enterprise v18 STIX') }}<br><b>Coverage engine:</b> {{ 'STIX-driven' if (coverage_engine or ec.get('coverage_engine')) != 'heuristic' else 'Heuristic' }}")
p.write_text(text)

# Patch other MITRE templates to preserve query params in subnav/forms if simple.
for name in ['mitre_data_sources.html','mitre_normalized_events.html']:
    p=Path('/mnt/data/stix_choice/app/templates')/name
    if p.exists():
        text=p.read_text()
        text=text.replace("?job={{ job_id }}", "?job={{ job_id }}&attack_mode={{ attack_mode or 'stix' }}&coverage_engine={{ coverage_engine or 'stix' }}")
        p.write_text(text)
