"""Cached Enterprise ATT&CK coverage construction.

The ATT&CK/STIX expansion path is intentionally expensive: it resolves detected
log sources to data components/data sources, scopes applicable techniques, folds
in observed evidence, checks enabled rules, and builds display rollups.  Page
routes should not do that work repeatedly.  This module centralizes the one
place where the model is rebuilt and stamps a small signature into result.json so
normal UI reads stay cheap.
"""
import hashlib
import json

from app.attack.versioned import (
    build_data_source_coverage,
    enterprise_coverage_assessment,
    build_enterprise_attack_coverage_model,
    coverage_engine_from_result,
    attack_version_from_result,
    set_attack_version,
)
from app.rules.engine import load_rules, attack_pipeline_diagnostics

COVERAGE_CACHE_VERSION = 'pcap-mapper-v2-coverage-cache-2026-07-15-8-upload-map-colors'


def _stable_json(value):
    return json.dumps(value, sort_keys=True, default=str, separators=(',', ':'))


def _hash(value):
    return hashlib.sha256(_stable_json(value).encode('utf-8')).hexdigest()


def coverage_input_signature(result):
    """Return a signature for result fields that influence ATT&CK coverage."""
    result = result or {}
    techniques = []
    for item in result.get('techniques', []) or []:
        tid = item.get('techniqueID') or item.get('technique_id')
        if tid:
            techniques.append({
                'id': tid,
                'confidence': item.get('confidence'),
                'source': item.get('source'),
                'hosts': item.get('hosts'),
            })
    normalized = []
    for item in result.get('normalized_events', []) or []:
        # Keep the signature bounded but sensitive to mapped evidence/log source.
        normalized.append({
            'platform': item.get('platform'),
            'log_source': item.get('log_source'),
            'event_type': item.get('event_type'),
            'attack_candidates': item.get('attack_candidates'),
            'confidence': item.get('confidence'),
        })
    payload = {
        'hosts': result.get('hosts', []) or [],
        'protocols': result.get('protocols', {}) or {},
        'log_sources': result.get('log_sources', []) or [],
        'normalized_event_summary': result.get('normalized_event_summary', {}) or {},
        'normalized_events': normalized,
        'techniques': techniques,
        'validated_techniques': result.get('validated_techniques', []) or [],
        'rule_validation_status': result.get('rule_validation_status'),
        'coverage_engine': coverage_engine_from_result(result),
        'attack_version': attack_version_from_result(result),
    }
    return _hash(payload)


def rules_signature(rules=None):
    """Return a compact signature for rule fields that influence coverage."""
    if rules is None:
        rules = load_rules()
    compact = []
    for rule in rules or []:
        compact.append({
            'id': rule.get('id') or rule.get('name') or rule.get('title'),
            'version': rule.get('version'),
            'enabled': rule.get('enabled', True),
            'attack': rule.get('attack') or rule.get('techniques') or [],
        })
    return _hash(compact)


def _has_cached_model(result):
    return bool(
        result.get('data_source_coverage') is not None
        and result.get('enterprise_coverage')
        and result.get('enterprise_attack_coverage_model')
    )


def coverage_cache_current(result, rules=None):
    meta = (result or {}).get('coverage_cache') or {}
    return (
        meta.get('version') == COVERAGE_CACHE_VERSION
        and meta.get('input_signature') == coverage_input_signature(result)
        and meta.get('rules_signature') == rules_signature(rules)
        and meta.get('coverage_engine') == coverage_engine_from_result(result)
        and meta.get('attack_version') == attack_version_from_result(result)
        and _has_cached_model(result)
    )


def ensure_coverage_cache(result, rules=None, force=False, include_diagnostics=True):
    """Build coverage only when result/rules changed; return (result, rebuilt)."""
    if result is None:
        result = {}
    meta = result.get('coverage_cache') or {}
    # Hot path: most page views should stop here.  Cache invalidation is handled
    # when rules change and when analysis/validation writes a new result.  Avoid
    # hashing thousands of events or loading the rule library on every request.
    if (
        not force
        and meta.get('version') == COVERAGE_CACHE_VERSION
        and not meta.get('stale')
        and meta.get('coverage_engine') == coverage_engine_from_result(result)
        and meta.get('attack_version') == attack_version_from_result(result)
        and _has_cached_model(result)
    ):
        return result, False

    if rules is None:
        rules = load_rules()
    input_sig = coverage_input_signature(result)
    rules_sig = rules_signature(rules)

    engine = coverage_engine_from_result(result)
    attack_version = attack_version_from_result(result)
    set_attack_version(attack_version)
    result['coverage_engine'] = engine
    result['attack_version_selected'] = attack_version
    result.pop('log_source_view_cache', None)
    coverage = build_data_source_coverage(result, engine)
    result['data_source_coverage'] = coverage
    enterprise = enterprise_coverage_assessment(result, rules, engine)
    result['enterprise_coverage'] = enterprise
    model = build_enterprise_attack_coverage_model(result, rules, engine)
    result['enterprise_attack_coverage_model'] = model
    if include_diagnostics:
        try:
            result['attack_pipeline_diagnostics'] = attack_pipeline_diagnostics(result, result.get('rule_validations'), rules)
        except Exception as exc:
            result['attack_pipeline_diagnostics'] = {'error': str(exc)}
    result['coverage_cache'] = {
        'version': COVERAGE_CACHE_VERSION,
        'input_signature': input_sig,
        'rules_signature': rules_sig,
        'coverage_engine': engine,
        'attack_version': attack_version,
        'data_source_techniques': len(coverage or []),
        'applicable_techniques': model.get('applicable_count', 0) if isinstance(model, dict) else 0,
        'theoretical_techniques': model.get('theoretical_count', 0) if isinstance(model, dict) else 0,
    }
    return result, True
