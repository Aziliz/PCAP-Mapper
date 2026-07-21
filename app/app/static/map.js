function safe(v, fallback){ return (v === undefined || v === null || v === '') ? fallback : v; }
function getJob(){ return new URLSearchParams(window.location.search).get('job') || ''; }
function showMapInfo(html){
  let p = document.getElementById('map-info');
  if(!p){
    const svg = document.getElementById('map');
    p = document.createElement('div');
    p.id = 'map-info';
    p.className = 'card map-info';
    svg.parentNode.appendChild(p);
  }
  p.innerHTML = html;
}
function flowQuery(f){
  return f.flow_id || [f.src_ip || '', f.dst_ip || '', f.protocol || '', f.dport || ''].join('|');
}
function openFlow(f){
  const job = getJob();
  const q = encodeURIComponent(flowQuery(f));
  window.location.href = '/communications?' + (job ? 'job=' + encodeURIComponent(job) + '&' : '') + 'q=' + q;
}
function draw(){
  const flows = JSON.parse(document.getElementById('flows').textContent || '[]');
  const hosts = JSON.parse(document.getElementById('hosts').textContent || '[]');
  const min = parseInt(document.getElementById('minp').value || '1');
  const svg = document.getElementById('map');
  svg.innerHTML = '';
  const W = svg.clientWidth || 900, H = 520;
  const hostIndex = {};
  hosts.forEach(h => { if(h.ip) hostIndex[h.ip] = h; });
  let nodes = {};
  let links = [];
  flows.filter(f => (f.packets || 0) >= min).slice(0,250).forEach(f => {
    if(!f.src_ip || !f.dst_ip) return;
    nodes[f.src_ip] = nodes[f.src_ip] || {id:f.src_ip, flows:0, packets:0, bytes:0};
    nodes[f.dst_ip] = nodes[f.dst_ip] || {id:f.dst_ip, flows:0, packets:0, bytes:0};
    nodes[f.src_ip].flows += 1;
    nodes[f.dst_ip].flows += 1;
    nodes[f.src_ip].packets += f.packets || 0;
    nodes[f.dst_ip].packets += f.packets || 0;
    nodes[f.src_ip].bytes += f.bytes || 0;
    nodes[f.dst_ip].bytes += f.bytes || 0;
    links.push(f);
  });
  let arr = Object.values(nodes);
  arr.forEach((n,i) => {
    let a = 2 * Math.PI * i / Math.max(1, arr.length);
    n.x = W/2 + Math.cos(a) * (Math.min(W,H)/2 - 60);
    n.y = H/2 + Math.sin(a) * (Math.min(W,H)/2 - 60);
  });
  function el(t){ return document.createElementNS('http://www.w3.org/2000/svg', t); }
  links.forEach(l => {
    let a = nodes[l.src_ip], b = nodes[l.dst_ip];
    if(!a || !b) return;
    let line = el('line');
    line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
    line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
    line.setAttribute('stroke', '#789');
    line.setAttribute('stroke-width', Math.min(6, 1 + Math.log(l.packets || 1)));
    line.setAttribute('class', 'map-link');
    line.style.cursor = 'pointer';
    line.innerHTML = '<title>' + safe(l.protocol,'') + ' ' + safe(l.packets,0) + ' packets</title>';
    line.addEventListener('click', () => {
      showMapInfo('<h3>Flow</h3>' +
        '<p><b>Source:</b> ' + safe(l.src_ip,'unknown') + '</p>' +
        '<p><b>Destination:</b> ' + safe(l.dst_ip,'unknown') + '</p>' +
        '<p><b>Protocol:</b> ' + safe(l.protocol,'unknown') + '</p>' +
        '<p><b>Port:</b> ' + safe(l.dport,'') + '</p>' +
        '<p><b>Packets:</b> ' + safe(l.packets,0) + '</p>' +
        '<p><b>Bytes:</b> ' + safe(l.bytes,0) + '</p>' +
        '<button id="open-flow">Open matching flow</button>');
      document.getElementById('open-flow').onclick = () => openFlow(l);
    });
    svg.appendChild(line);
  });
  arr.forEach(n => {
    let c = el('circle');
    c.setAttribute('cx', n.x); c.setAttribute('cy', n.y);
    c.setAttribute('r', 14);
    c.setAttribute('fill', '#2962ff');
    c.setAttribute('class', 'map-node');
    c.style.cursor = 'pointer';
    c.innerHTML = '<title>' + n.id + '</title>';
    c.addEventListener('click', () => {
      const h = hostIndex[n.id] || {};
      showMapInfo('<h3>Node</h3>' +
        '<p><b>IP:</b> ' + n.id + '</p>' +
        '<p><b>MAC:</b> ' + safe(h.mac, 'unknown') + '</p>' +
        '<p><b>Hostname:</b> ' + safe(h.hostname, 'unknown') + '</p>' +
        '<p><b>OS:</b> ' + safe(h.os, 'unknown') + '</p>' +
        '<p><b>Role:</b> ' + safe(h.role, 'unknown') + '</p>' +
        '<p><b>Flows:</b> ' + n.flows + '</p>' +
        '<p><b>Packets:</b> ' + n.packets + '</p>' +
        '<p><b>Bytes:</b> ' + n.bytes + '</p>');
    });
    svg.appendChild(c);
    let tx = el('text');
    tx.setAttribute('x', n.x + 16); tx.setAttribute('y', n.y + 4);
    tx.setAttribute('font-size', '12'); tx.setAttribute('fill', 'currentColor');
    tx.textContent = n.id;
    svg.appendChild(tx);
  });
}
draw();
