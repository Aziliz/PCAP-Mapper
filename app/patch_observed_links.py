from pathlib import Path
p=Path('/mnt/data/pcap30/app/web.py')
s=p.read_text()
insert=r'''

def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _attack_ids_from_obj(obj):
    ids = []
    if not isinstance(obj, dict):
        return ids
    for key in ('techniqueID','technique_id','attack_id','attackId','id'):
        v = obj.get(key)
        if isinstance(v, str) and v.upper().startswith('T'):
            ids.append(v)
    for key in ('attack','attacks','attack_ids','attack_candidates','techniques','mitre','validated_techniques'):
        for item in _as_list(obj.get(key)):
            if isinstance(item, str) and item.upper().startswith('T'):
                ids.append(item)
            elif isinstance(item, dict):
                ids.extend(_attack_ids_from_obj(item))
    return sorted({x for x in ids if x})


def _first_ip_from_obj(obj, prefer_source=True):
    if not isinstance(obj, dict):
        return ''
    source_keys = ('src_ip','source_ip','source','src','client_ip','remote_ip','host_ip','ip')
    other_keys = ('dst_ip','destination_ip','destination','dst','server_ip','peer_ip')
    keys = source_keys + other_keys if prefer_source else other_keys + source_keys
    for key in keys:
        v = obj.get(key)
        if isinstance(v, str) and v and any(ch.isdigit() for ch in v):
            return v
    return ''


def _short_text(value, limit=220):
    if value is None:
        return ''
    if not isinstance(value, str):
        try:
            value = json.dumps(value, default=str)
        except Exception:
            value = str(value)
    value = ' '.join(value.split())
    return value[:limit] + ('...' if len(value) > limit else '')


def _observed_drilldown_index(result):
    """Build technique -> source IP/details for observed MITRE overlay cards.

    This is intentionally tolerant because result structures vary between parser
    generations, imported jobs, and legacy/STIX coverage modes.
    """
    idx = {}
    def add(tid, source, obj):
        if not tid:
            return
        row = idx.setdefault(tid, {
            'source_ip': '', 'dst_ip': '', 'host': '', 'sources': set(),
            'events': 0, 'flows': 0, 'evidence': [], 'event_ids': [], 'flow_ids': []
        })
        row['sources'].add(source)
        if source == 'event': row['events'] += 1
        if source == 'flow': row['flows'] += 1
        if not row['source_ip']:
            row['source_ip'] = _first_ip_from_obj(obj, True)
        if not row['dst_ip']:
            for k in ('dst_ip','destination_ip','destination','dst','server_ip'):
                if isinstance(obj, dict) and obj.get(k): row['dst_ip'] = str(obj.get(k)); break
        if not row['host']:
            for k in ('host','hostname','asset','computer','computer_name'):
                if isinstance(obj, dict) and obj.get(k): row['host'] = str(obj.get(k)); break
        if isinstance(obj, dict):
            eid = obj.get('event_id') or obj.get('id')
            fid = obj.get('flow_id') or obj.get('uid')
            if eid and len(row['event_ids']) < 5: row['event_ids'].append(str(eid))
            if fid and len(row['flow_ids']) < 5: row['flow_ids'].append(str(fid))
            ev = obj.get('evidence') or obj.get('reason') or obj.get('rationale') or obj.get('raw') or obj.get('summary') or obj.get('event_type') or obj.get('protocol')
            ev = _short_text(ev)
            if ev and ev not in row['evidence'] and len(row['evidence']) < 5:
                row['evidence'].append(ev)
    for e in result.get('normalized_events', []) or []:
        for tid in _attack_ids_from_obj(e):
            add(tid, 'event', e)
    for f in result.get('flows', []) or []:
        for tid in _attack_ids_from_obj(f):
            add(tid, 'flow', f)
    for t in result.get('techniques', []) or []:
        for tid in _attack_ids_from_obj(t):
            add(tid, 'technique', t)
    for row in idx.values():
        row['sources'] = ', '.join(sorted(row['sources']))
        row['evidence_text'] = ' | '.join(row['evidence'])
    return idx


def annotate_observed_drilldowns(result):
    ec = result.get('enterprise_coverage') or {}
    states = ec.get('coverage_states') or []
    if not states:
        return result
    idx = _observed_drilldown_index(result)
    for st in states:
        tid = st.get('techniqueID') or st.get('technique_id')
        if not tid or not st.get('observed'):
            continue
        d = idx.get(tid, {})
        st['observed_source_ip'] = d.get('source_ip', '')
        st['observed_dst_ip'] = d.get('dst_ip', '')
        st['observed_host'] = d.get('host', '')
        st['observed_sources'] = d.get('sources', '')
        st['observed_event_count'] = d.get('events', 0)
        st['observed_flow_count'] = d.get('flows', 0)
        st['observed_evidence'] = d.get('evidence_text', '')
        st['observed_event_ids'] = d.get('event_ids', [])
        st['observed_flow_ids'] = d.get('flow_ids', [])
    result['enterprise_coverage'] = ec
    return result
'''
marker='def build_mitre_page_context'
if insert.strip() not in s:
    s=s.replace(marker, insert+'\n\n'+marker)
# call annotate before return
old="""    tactic_rollups = build_tactic_rollups(result, rules, attack_mode=attack_mode)
    return result, jid, attack_mode, tactic_rollups, coverage_engine
"""
new="""    result = annotate_observed_drilldowns(result)
    tactic_rollups = build_tactic_rollups(result, rules, attack_mode=attack_mode)
    return result, jid, attack_mode, tactic_rollups, coverage_engine
"""
s=s.replace(old,new)
p.write_text(s)

# template mitre
p=Path('/mnt/data/pcap30/app/templates/mitre.html')
s=p.read_text()
old='''data-technique-name="{{ t.get('name') }}" data-detail="State: {{ t.get('state','') }} | Tactic: {{ t.get('tactic','') }} | Applicable: {{ 'Yes' if t.get('applicable', True) else 'No' }} | Rule: {{ 'Yes' if t.get('rule') else 'No' }} | Validated: {{ 'Yes' if t.get('validated') else 'No' }}{% if t.get('external_visibility') %} | Out of Enterprise Visibility: {{ t.get('external_visibility_reason') }}{% elif not t.get('applicable', True) %} | Not Applicable: outside detected OS/log-source scope{% endif %}"'''
new='''data-technique-name="{{ t.get('name') }}" data-observed-ip="{{ t.get('observed_source_ip','') }}" data-observed-dst="{{ t.get('observed_dst_ip','') }}" data-observed-host="{{ t.get('observed_host','') }}" data-observed-sources="{{ t.get('observed_sources','') }}" data-observed-events="{{ t.get('observed_event_count',0) }}" data-observed-flows="{{ t.get('observed_flow_count',0) }}" data-observed-evidence="{{ t.get('observed_evidence','') }}" data-detail="State: {{ t.get('state','') }} | Tactic: {{ t.get('tactic','') }} | Applicable: {{ 'Yes' if t.get('applicable', True) else 'No' }} | Rule: {{ 'Yes' if t.get('rule') else 'No' }} | Validated: {{ 'Yes' if t.get('validated') else 'No' }}{% if t.get('external_visibility') %} | Out of Enterprise Visibility: {{ t.get('external_visibility_reason') }}{% elif not t.get('applicable', True) %} | Not Applicable: outside detected OS/log-source scope{% endif %}"'''
if old in s:
    s=s.replace(old,new)
else:
    # less exact fallback insert after technique name attr
    s=s.replace('data-technique-name="{{ t.get(\'name\') }}"','data-technique-name="{{ t.get(\'name\') }}" data-observed-ip="{{ t.get(\'observed_source_ip\',\'\') }}" data-observed-dst="{{ t.get(\'observed_dst_ip\',\'\') }}" data-observed-host="{{ t.get(\'observed_host\',\'\') }}" data-observed-sources="{{ t.get(\'observed_sources\',\'\') }}" data-observed-events="{{ t.get(\'observed_event_count\',0) }}" data-observed-flows="{{ t.get(\'observed_flow_count\',0) }}" data-observed-evidence="{{ t.get(\'observed_evidence\',\'\') }}"')
old_aside='''<aside id="techniquePanel" class="technique-panel" aria-live="polite"><button type="button" id="techniquePanelClose" class="panel-close">×</button><h3 id="techniquePanelTitle">Technique detail</h3><p id="techniquePanelDetail" class="muted"></p><p class="muted">This panel explains the selected technique state using the Unified Coverage Model.</p><div id="observedDrillLinks" class="button-row" style="display:none"><a class="btn" id="obsAssets" href="#">Assets</a><a class="btn" id="obsComms" href="#">Communications</a><a class="btn" id="obsLogs" href="#">Log Sources</a><a class="btn" id="obsEvents" href="#">Events</a></div></aside>'''
new_aside='''<aside id="techniquePanel" class="technique-panel" aria-live="polite"><button type="button" id="techniquePanelClose" class="panel-close">×</button><h3 id="techniquePanelTitle">Technique detail</h3><p id="techniquePanelDetail" class="muted"></p><div id="observedTriggerDetail" class="mini-card" style="display:none"></div><p class="muted">This panel explains the selected technique state using the Unified Coverage Model.</p><div id="observedDrillLinks" class="button-row" style="display:none"><a class="btn" id="obsAssets" href="#">Assets</a><a class="btn" id="obsComms" href="#">Communications</a><a class="btn" id="obsLogs" href="#">Log Sources</a><a class="btn" id="obsEvents" href="#">Events</a></div></aside>'''
s=s.replace(old_aside,new_aside)
old_js='''    const links=document.getElementById('observedDrillLinks');
    const tid=card.dataset.techniqueId || '';
    const q=tid || card.dataset.techniqueName || card.dataset.title || '';
    const job='{{ job_id or '' }}';
    const sep=job ? '&' : '?';
    const baseJob=job ? ('?job=' + encodeURIComponent(job)) : '';
    if(links){
      if(card.dataset.observed==='1'){
        links.style.display='flex';
        document.getElementById('obsAssets').href='/assets' + baseJob + sep + 'q=' + encodeURIComponent(q);
        document.getElementById('obsComms').href='/communications' + baseJob + sep + 'q=' + encodeURIComponent(q);
        document.getElementById('obsLogs').href='/log-sources' + baseJob + sep + 'q=' + encodeURIComponent(q);
        document.getElementById('obsEvents').href='/events' + baseJob + sep + 'attack=' + encodeURIComponent(tid) + '&q=' + encodeURIComponent(q);
      } else {
        links.style.display='none';
      }
    }
'''
new_js='''    const links=document.getElementById('observedDrillLinks');
    const trigger=document.getElementById('observedTriggerDetail');
    const tid=card.dataset.techniqueId || '';
    const q=tid || card.dataset.techniqueName || card.dataset.title || '';
    const ip=card.dataset.observedIp || '';
    const dst=card.dataset.observedDst || '';
    const host=card.dataset.observedHost || '';
    const evidence=card.dataset.observedEvidence || '';
    const sources=card.dataset.observedSources || '';
    const job='{{ job_id or '' }}';
    const sep=job ? '&' : '?';
    const baseJob=job ? ('?job=' + encodeURIComponent(job)) : '';
    function esc(v){ return String(v || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
    if(links){
      if(card.dataset.observed==='1'){
        links.style.display='flex';
        if(trigger){
          trigger.style.display='block';
          trigger.innerHTML='<b>Observed trigger</b><br>'+
            '<small>Source IP: '+esc(ip || 'unknown')+'</small><br>'+
            (dst ? '<small>Destination IP: '+esc(dst)+'</small><br>' : '')+
            (host ? '<small>Host/asset: '+esc(host)+'</small><br>' : '')+
            '<small>Evidence sources: '+esc(sources || 'observed analysis data')+'</small><br>'+
            '<small>Events: '+esc(card.dataset.observedEvents || '0')+' · Flows: '+esc(card.dataset.observedFlows || '0')+'</small>'+
            (evidence ? '<p class="muted">'+esc(evidence)+'</p>' : '<p class="muted">No detailed evidence text was stored for this observation.</p>');
        }
        const ipParam=encodeURIComponent(ip || q);
        document.getElementById('obsAssets').href='/assets' + baseJob + sep + 'ip=' + ipParam;
        document.getElementById('obsComms').href='/communications' + baseJob + sep + 'ip=' + ipParam + '&src=' + ipParam;
        document.getElementById('obsLogs').href='/log-sources' + baseJob + sep + 'ip=' + ipParam;
        document.getElementById('obsEvents').href='/events' + baseJob + sep + 'attack=' + encodeURIComponent(tid);
      } else {
        links.style.display='none';
        if(trigger) trigger.style.display='none';
      }
    }
'''
if old_js not in s:
    raise SystemExit('mitre js block not found')
s=s.replace(old_js,new_js)
p.write_text(s)

# assets ip param
p=Path('/mnt/data/pcap30/app/templates/assets.html')
s=p.read_text()
s=s.replace("if (params.get('q')) assetSearch.value = params.get('q');", "if (params.get('ip')) assetSearch.value = params.get('ip');\n  else if (params.get('q')) assetSearch.value = params.get('q');")
p.write_text(s)
# communications params
p=Path('/mnt/data/pcap30/app/templates/communications.html')
s=p.read_text()
s=s.replace("const q = qs('q'); if(q){ document.getElementById('q').value = q; }", "const ip = qs('ip');\n  const srcParam = qs('src');\n  const q = qs('q');\n  if(ip){ document.getElementById('src').value = ip; document.getElementById('q').value = ip; }\n  else if(srcParam){ document.getElementById('src').value = srcParam; }\n  if(q){ document.getElementById('q').value = q; }")
p.write_text(s)
# log sources ip param sets search
p=Path('/mnt/data/pcap30/app/templates/log_sources.html')
s=p.read_text()
s=s.replace("if(logParams.get('q')) document.getElementById('logQ').value = logParams.get('q');", "if(logParams.get('ip')) document.getElementById('logQ').value = logParams.get('ip');\nelse if(logParams.get('q')) document.getElementById('logQ').value = logParams.get('q');")
p.write_text(s)
