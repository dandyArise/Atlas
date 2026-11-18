'use strict';
const $=id=>document.getElementById(id);
const text=(tag,value)=>{const e=document.createElement(tag);e.textContent=value;return e;};
const paths={
 globe:'<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18M5 6.5h14M5 17.5h14"/>',
 search:'<circle cx="10.5" cy="10.5" r="7"/><path d="m16 16 5 5"/>',
 clock:'<circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/>',
 layers:'<path d="m3 7 9-5 9 5-9 5-9-5Zm0 5 9 5 9-5M3 17l9 5 9-5"/>',
 'chevron-down':'<path d="m6 9 6 6 6-6"/>','chevron-right':'<path d="m9 5 7 7-7 7"/>','chevron-left':'<path d="m15 5-7 7 7 7"/>',
 power:'<path d="M12 2v10M6 5a9 9 0 1 0 12 0"/>',
 app:'<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M3 8h18M8 8v13"/>',
 server:'<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M12 6.5h5M12 17.5h5"/>',
 connections:'<circle cx="5" cy="5" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="12" cy="19" r="2"/><path d="M7 5h10M5 7v5h14V7M12 12v5"/>',
 database:'<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 4 16 4 16 0V5M4 12c0 4 16 4 16 0"/>',
 laptop:'<rect x="5" y="4" width="14" height="12" rx="1"/><path d="m5 16-3 4h20l-3-4M9 20h6"/>',
 chart:'<path d="M4 20V12h3v8M10.5 20V4h3v16M17 20V8h3v12"/>',
 calendar:'<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M7 2v6M17 2v6M3 11h18"/>',
 radio:'<circle cx="12" cy="12" r="2"/><path d="M7 7a7 7 0 0 0 0 10M17 7a7 7 0 0 1 0 10M4 4a11 11 0 0 0 0 16M20 4a11 11 0 0 1 0 16"/>',
 alert:'<path d="m12 3 10 18H2L12 3Z" fill="currentColor" stroke="currentColor"/><path d="M12 9v5m0 3v.2" stroke="white" stroke-width="2"/>',
 info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.2"/>',
 pin:'<path d="M19 10c0 5-7 12-7 12S5 15 5 10a7 7 0 0 1 14 0Z"/><circle cx="12" cy="10" r="2.5"/>',
 shield:'<path d="m12 2 8 3v6c0 6-8 11-8 11S4 17 4 11V5l8-3Z"/><path d="m8 12 3 3 5-6"/>',
 close:'<path d="m6 6 12 12M18 6 6 18"/>',
 refresh:'<path d="M20 7V2m0 5h-5M4 17v5m0-5h5M20 7a9 9 0 0 0-16 1m0 9a9 9 0 0 0 16-1"/>',
 expand:'<path d="M9 3H3v6m12-6h6v6M3 15v6h6m12-6v6h-6"/>',
 target:'<circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2"/><path d="M12 1v4m0 14v4M1 12h4m14 0h4"/>',
 settings:'<path d="m9 3 1-1h4l1 3 3 1 3 1v4l-2 1-1 3 1 3-3 3-3-1-3 1-1 2H5l-1-3-2-2 1-3-1-3 2-2 1-3 4-1Z"/><circle cx="11" cy="12" r="3"/>'
};
function icon(name,className=''){const e=document.createElementNS('http://www.w3.org/2000/svg','svg');e.setAttribute('viewBox','0 0 24 24');e.setAttribute('fill','none');e.setAttribute('stroke','currentColor');e.setAttribute('stroke-linecap','round');e.setAttribute('stroke-linejoin','round');e.setAttribute('aria-hidden','true');e.setAttribute('class',`icon ${className}`);e.innerHTML=paths[name]||paths.app;return e;}
document.querySelectorAll('[data-icon]').forEach(e=>e.replaceWith(icon(e.dataset.icon,e.className)));
let mode='live',offset=0,data=null,sequence=0,selected=null,selectedGroup=null,openGroups=new Set(),expandedRows=new Set(),settingOrigin=false,origin=null,appIcons={},countryNames={Singapore:'Singapour'};
const when=t=>t?new Date(t*1000).toLocaleString('fr-FR'):'Jamais';
const protocol=r=>(r.protocol||'TCP')+(r.quic_possible?' · QUIC possible':'');
const countryName=v=>countryNames[v]||v||'Non localisé';
const rowAlerts=r=>Array.isArray(r.alerts)?r.alerts:[];
const friendlyNames={'brave.exe':'Brave','chrome.exe':'Chrome','firefox.exe':'Firefox','msedge.exe':'Edge','chatgpt.exe':'ChatGPT','codex.exe':'Codex','steam.exe':'Steam','steamwebhelper.exe':'Steam WebHelper','discord.exe':'Discord','onedrive.exe':'OneDrive','spotify.exe':'Spotify','teams.exe':'Teams','explorer.exe':'Explorateur','svchost.exe':'Services Windows'};
const friendly=r=>friendlyNames[r.app?.toLowerCase()]||r.app;
try{origin=JSON.parse(localStorage.getItem('atlas-origin'));if(!Array.isArray(origin)||origin.length!==2||!origin.every(Number.isFinite)||Math.abs(origin[0])>90||Math.abs(origin[1])>180)origin=null;}catch{origin=null;}
const map=L.map('map',{worldCopyJump:true,minZoom:1,maxZoom:17,zoomSnap:.25}).setView([25,8],1.75);
const land=L.layerGroup().addTo(map),lines=L.layerGroup().addTo(map),markers=L.layerGroup().addTo(map);
const tiles=L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:19,attribution:'© <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noreferrer">OpenStreetMap</a> contributors'});
map.attributionControl.setPrefix('<a href="https://leafletjs.com" target="_blank" rel="noreferrer">Leaflet</a> · Natural Earth');
fetch('/world.json').then(r=>{if(!r.ok)throw Error('Fond de carte indisponible');return r.json();}).then(world=>L.geoJSON(world,{style:{color:'#a9c9df',weight:.8,fillColor:'#eaf0f6',fillOpacity:1},interactive:false}).addTo(land)).catch(e=>{$('map-message').textContent=e.message;});
fetch('/country-names.json').then(r=>r.json()).then(names=>{countryNames={...names,Singapore:'Singapour'};if(data)render();}).catch(()=>{});
$('detailed-map').onchange=()=>{if($('detailed-map').checked){tiles.addTo(map);land.remove();}else{tiles.remove();land.addTo(map);}};
tiles.on('tileerror',()=>{$('map-message').textContent='Fond OSM indisponible. Désactivez Détails OSM pour revenir à la carte locale.';});
function originUi(){$('clear-origin').hidden=!origin;$('origin').replaceChildren(icon('laptop'),text('span',settingOrigin?'Cliquez votre départ…':origin?'Départ':'Définir le départ'));}
$('origin').onclick=()=>{settingOrigin=!settingOrigin;originUi();};
$('clear-origin').onclick=()=>{origin=null;localStorage.removeItem('atlas-origin');originUi();drawMap();};
map.on('click',e=>{if(!settingOrigin)return;origin=[e.latlng.lat,e.latlng.wrap().lng];localStorage.setItem('atlas-origin',JSON.stringify(origin));settingOrigin=false;originUi();drawMap();});originUi();
map.on('zoomend moveend',()=>drawMap());
function groupKey(r){switch($('grouping').value){case'country':return r.geo?.country||'Pays non localisé';case'domain':return r.domains?.[0]||'Domaine inconnu';case'server':return r.remote;default:return r.app;}}
function visibleRows(){return !data?[]:selectedGroup?data.rows.filter(r=>groupKey(r)===selectedGroup):data.rows;}
function selectRow(r){selected=r.id;openGroups.add(groupKey(r));renderDetails(r);drawMap();renderTree();}
function renderDetails(r){
 $('detail-placeholder').hidden=true;$('detail-title').textContent='Détails de la connexion';$('detail-body').replaceChildren();$('detail-extra').replaceChildren();
 const fields={'Application':friendly(r),'Pays':r.geo?countryName(r.geo.country):'Non localisé','Domaine':r.domains?.[0]||'—','Destination':`${r.remote}:${r.port}`,'Protocole':protocol(r),'État':r.active?r.state:'Terminée'};
 for(const[k,v]of Object.entries(fields)){const pair=document.createElement('div');const dd=text('dd',v);dd.title=v;pair.append(text('dt',`${k} :`),dd);$('detail-body').append(pair);}
 const extras={'Exécutable':r.path||'Chemin inaccessible','Adresse locale':`${r.local}:${r.local_port}`,'Première vue':when(r.first),'Dernière vue':when(r.last),'Localisation':r.geo?`${r.geo.city||''} · ${countryName(r.geo.country)}`:'Non localisée','Domaines possibles':r.domains?.join(', ')||'Aucun dans le cache DNS'};
 if(r.protocol==='UDP')extras['Datagrammes']=`${r.sent||0} émis · ${r.received||0} reçus`;
 for(const[k,v]of Object.entries(extras))$('detail-extra').append(text('dt',k),text('dd',v));
 $('detail-alerts').replaceChildren();for(const a of rowAlerts(r)){const e=document.createElement('div');e.append(text('strong',`${a.source} · ${a.confidence==='ip_exact'?'IP exacte':'Domaine possible'} · ${a.indicator}`),text('p',`${a.description} Vérifié le ${when(a.evaluated)}.`));$('detail-alerts').append(e);}
}
$('more-details').onclick=()=>{const open=$('detail-extra').hidden;$('detail-extra').hidden=!open;$('more-details').setAttribute('aria-expanded',String(open));};
function appIcon(r){if(appIcons[r.path]){const img=document.createElement('img');img.src=appIcons[r.path];img.className='app-icon';img.alt='';img.width=26;img.height=26;img.onerror=()=>img.replaceWith(fallbackIcon(r));return img;}return fallbackIcon(r);}
function fallbackIcon(r){const span=document.createElement('span');span.className='fallback-icon';span.append(icon(r?.app==='svchost.exe'?'settings':r?.app?.startsWith('PID')?'layers':'app'));return span;}
function renderTree(){
 const focused=document.activeElement?.dataset?.row;
 const groups=new Map();for(const r of data.rows){const key=groupKey(r);if(!groups.has(key))groups.set(key,[]);groups.get(key).push(r);}
 $('tree').replaceChildren();
 for(const[key,rows]of [...groups].sort((a,b)=>b[1].length-a[1].length)){
  const d=document.createElement('details');d.className='group';d.open=openGroups.has(key);
  const s=document.createElement('summary'),label=document.createElement('span');label.className='group-label';label.title=key;
  const grouping=$('grouping').value;label.append(text('strong',grouping==='app'?friendly(rows[0]):grouping==='country'?countryName(key):key));
  if(grouping==='app'&&friendly(rows[0])!==key)label.append(text('small',`(${key})`));
  s.append(icon('chevron-right','disclosure'),grouping==='app'?appIcon(rows[0]):icon(grouping==='server'?'server':'globe','fallback-icon'),label);
  if(rows.some(r=>rowAlerts(r).length)){const a=icon('alert','alert-dot');s.append(a);}
  const count=text('span',`(${rows.length})`);count.className='count';s.append(count);d.append(s);
  d.ontoggle=()=>{if(!d.isConnected)return;if(d.open)openGroups.add(key);else openGroups.delete(key);};
  const filter=document.createElement('button');filter.className='group-filter';filter.append(icon('target'),text('span',selectedGroup===key?'Afficher tous les groupes':'Isoler sur la carte'));filter.onclick=()=>{selectedGroup=selectedGroup===key?null:key;drawMap();renderTree();};d.append(filter);
  const shown=expandedRows.has(key)?rows:rows.slice(0,3);const selectedRow=rows.find(r=>r.id===selected);if(selectedRow&&!shown.includes(selectedRow))shown.push(selectedRow);
  for(const r of shown){const b=document.createElement('button');b.dataset.row=String(r.id);b.className=`leaf ${r.id===selected?'selected':''} ${rowAlerts(r).length?'flagged':''}`;const dot=rowAlerts(r).length?icon('alert'):text('span','');if(!rowAlerts(r).length)dot.className='leaf-dot';const name=text('span',grouping==='server'?r.app:r.remote);name.className='leaf-name';b.append(dot,name,text('small',r.quic_possible?'UDP/443':`${r.protocol||'TCP'} :${r.port}`),icon('chevron-right'));b.title=`${r.app} · ${protocol(r)} · ${countryName(r.geo?.country)}`;b.onclick=()=>selectRow(r);d.append(b);}
  if(rows.length>3){const more=text('button',expandedRows.has(key)?'Réduire':`Voir les ${rows.length} connexions`);more.className='group-filter';more.onclick=()=>{if(expandedRows.has(key))expandedRows.delete(key);else expandedRows.add(key);renderTree();};d.append(more);}
  $('tree').append(d);
 }
 if(!groups.size){const e=text('p','Aucune connexion pour ces filtres.');e.className='empty';$('tree').append(e);}
 if(focused){const match=[...$('tree').querySelectorAll('[data-row]')].find(e=>e.dataset.row===focused);match?.focus({preventScroll:true});}
}
function curvedRoute(a,b){const start=map.project(a),end=map.project(b),bend=Math.min(80,Math.abs(end.x-start.x)*.14),mid=L.point((start.x+end.x)/2,(start.y+end.y)/2-bend),points=[];for(let i=0;i<=30;i++){const t=i/30;points.push(map.unproject(L.point((1-t)**2*start.x+2*(1-t)*t*mid.x+t*t*end.x,(1-t)**2*start.y+2*(1-t)*t*mid.y+t*t*end.y)));}return points;}
function drawMap(){
 if(!data)return;markers.clearLayers();lines.clearLayers();const rows=visibleRows(),groups=new Map();
 for(const r of rows){if(!r.geo||!Number.isFinite(r.geo.lat)||!Number.isFinite(r.geo.lon))continue;const key=`${Math.round(r.geo.lat*2)},${Math.round(r.geo.lon*2)}`;if(!groups.has(key))groups.set(key,[]);groups.get(key).push(r);}
 if(origin){const computer=L.divIcon({className:'origin-marker',html:icon('laptop').outerHTML,iconSize:[44,44],iconAnchor:[22,22]});L.marker(origin,{icon:computer,zIndexOffset:1000,title:'Point de départ choisi manuellement'}).bindTooltip('Départ choisi manuellement').addTo(markers);}
 const labels=[],size=map.getSize();
 for(const group of [...groups.values()].sort((a,b)=>b.length-a.length)){
  const r=group[0],alert=group.some(x=>rowAlerts(x).length),chosen=group.some(x=>x.id===selected),pos=[r.geo.lat,r.geo.lon];
  const color=alert?'#ef8718':'#009ca4';
  if(origin){const route=curvedRoute(origin,pos);L.polyline(route,{color:'#e9ffff',weight:chosen?6:4,opacity:.65,interactive:false}).addTo(lines);L.polyline(route,{color:alert?'#de851d':'#078c9a',weight:chosen?3:1.8,opacity:.8,interactive:false}).addTo(lines);}
  L.circleMarker(pos,{radius:chosen?12:10,color:'#fff',weight:3,fillColor:color,fillOpacity:.95,className:'destination-ring'}).on('click',()=>selectRow(r)).addTo(markers);
  const m=L.circleMarker(pos,{radius:chosen?5:4,color:color,weight:1,fillColor:alert?'#ffe0b6':'#6de7dd',fillOpacity:1}).addTo(markers);
  const point=map.latLngToContainerPoint(pos),labelText=map.getZoom()>3&&r.geo.city?r.geo.city:countryName(r.geo.country),width=Math.min(170,labelText.length*8+24);
  const show=point.x>width/2&&point.x<size.x-width/2&&point.y>64&&point.y<size.y-45&&labels.length<12&&!labels.some(p=>p.text===labelText||(Math.abs(p.x-point.x)<(p.width+width)/2&&Math.abs(p.y-point.y)<38));
  if(show)labels.push({x:point.x,y:point.y,width,text:labelText});
  m.bindTooltip(text('span',labelText),{permanent:show,direction:'top',offset:[0,-12],className:'destination-label',opacity:1});m.on('click',()=>selectRow(r));
 }
 const located=rows.filter(r=>r.geo).length,local=rows.filter(r=>!r.public&&!r.geo).length;$('coverage').textContent=`${located} localisées · ${local} locales · ${rows.length-located-local} inconnues`;
 $('map-message').textContent=selectedGroup?`Carte : ${selectedGroup} · page courante`:!rows.length?'Aucune connexion dans cette sélection.':!located?(data.health.geo_enabled?'Localisation des IP publiques en cours…':'Activez la géolocalisation pour placer vos destinations.'):'';
}
$('fit-map').onclick=()=>{const points=visibleRows().filter(r=>r.geo).map(r=>[r.geo.lat,r.geo.lon]);if(origin)points.push(origin);if(points.length)map.fitBounds(points,{paddingTopLeft:[55,80],paddingBottomRight:[55,55],maxZoom:6});else map.setView([25,8],1.75);};
function render(){const h=data.health;
 $('connections').textContent=data.total;$('apps').textContent=data.apps;$('destinations').textContent=data.destinations;$('alert-count').textContent=data.alert_count||0;$('page').textContent=data.total?`${offset+1}–${offset+data.rows.length} / ${data.total}`:'0 résultat';$('previous').disabled=offset===0;$('next').disabled=offset+200>=data.total;
 const stale=Date.now()/1000-h.last>12;$('status').textContent=h.last?`${stale?'En retard · ':''}${when(h.last)}`:'Première capture…';$('capture-time').textContent=h.last?when(h.last):'';
 const u=h.udp;$('udp-status').textContent=u?.available?'Actif':u?.error||'Indisponible';$('udp-status').title=u?.available?`${u.events.toLocaleString('fr-FR')} événements observés`:u?.error||'';$('udp-status').parentElement.classList.toggle('unavailable',!u?.available);
 const errors=[h.error,h.geo_error,u?.dropped?`${u.dropped} événements/buffers UDP perdus.`:null,u?.rejected?`${u.rejected} événements UDP non décodés.`:null].filter(Boolean);$('error').hidden=!errors.length;$('error').textContent=errors.join(' ');$('geo-title').textContent=`Géolocalisation ${h.geo_enabled?'activée':'désactivée'}`;$('geo').textContent=h.geo_enabled?'Désactiver':'Activer';
 const current=$('country').value,options=['',...data.countries];if(JSON.stringify([...$('country').options].map(o=>o.value))!==JSON.stringify(options)){$('country').replaceChildren(...options.map(v=>{const o=text('option',v?countryName(v):'Tous');o.value=v;return o;}));$('country').value=current;}
 renderTree();drawMap();const r=data.rows.find(r=>r.id===selected);if(r)renderDetails(r);
}
async function refresh(){const n=++sequence,p=new URLSearchParams({mode,q:$('search').value,offset,protocol:$('protocol').value,country:$('country').value,alerts:$('alerts').value});if(mode==='history'&&$('date').value){const d=new Date(`${$('date').value}T00:00:00`);p.set('since',Math.floor(d/1000));d.setDate(d.getDate()+1);p.set('until',Math.floor(d/1000)-1);}try{const r=await fetch(`/api/connections?${p}`);if(!r.ok)throw Error(`HTTP ${r.status}`);const next=await r.json();if(n!==sequence)return;data=next;if(offset>=data.total&&offset>0){offset=0;return refresh();}render();}catch(e){if(n!==sequence)return;$('status').textContent='Collecteur inaccessible';$('error').hidden=false;$('error').textContent=`${e.message} · Lancez Atlas pour reprendre l’observation.`;}}
function changed(){offset=0;selectedGroup=null;selected=null;$('detail-title').textContent='Détails de la connexion';$('detail-placeholder').hidden=false;$('detail-body').replaceChildren();$('detail-extra').replaceChildren();$('detail-alerts').replaceChildren();refresh();}
function setMode(v){mode=v;for(const id of ['live','history']){$(id).classList.toggle('selected',id===v);$(id).setAttribute('aria-pressed',id===v);}$('date-label').hidden=v!=='history';changed();}
$('live').onclick=()=>setMode('live');$('history').onclick=()=>setMode('history');let searchTimer;$('search').oninput=()=>{clearTimeout(searchTimer);searchTimer=setTimeout(changed,200);};for(const id of ['date','protocol','country','alerts'])$(id).onchange=changed;
function setGrouping(value){$('grouping').value=value;document.querySelectorAll('[data-group]').forEach(e=>e.setAttribute('aria-pressed',String(e.dataset.group===value)));openGroups.clear();selectedGroup=null;if(data){renderTree();drawMap();}}
$('grouping').onchange=()=>setGrouping($('grouping').value);document.querySelectorAll('[data-group]').forEach(b=>b.onclick=()=>setGrouping(b.dataset.group));
$('clear').onclick=()=>{for(const id of ['search','date','protocol','country','alerts'])$(id).value='';changed();};$('previous').onclick=()=>{offset=Math.max(0,offset-200);selectedGroup=null;refresh();};$('next').onclick=()=>{offset+=200;selectedGroup=null;refresh();};
async function post(url){const r=await fetch(url,{method:'POST',headers:{'X-Atlas-Local':'1'}});if(!r.ok)throw Error(await r.text());return r.json();}
$('geo').onclick=async()=>{if(!data)return;$('geo').disabled=true;try{await post(`/api/geo?enabled=${!data.health.geo_enabled}`);await refresh();}catch(e){$('error').hidden=false;$('error').textContent=e.message;}finally{$('geo').disabled=false;}};
async function loadIcons(){try{const r=await fetch('/api/icons');if(!r.ok)return;const next=await r.json();if(JSON.stringify(next)!==JSON.stringify(appIcons)){appIcons=next;if(data)renderTree();}}catch{/* Existing vector fallback remains visible. */}}
async function loadLists(){try{const r=await fetch('/api/lists');if(!r.ok)throw Error('Listes indisponibles');const lists=await r.json();$('dns-status').textContent=lists.dns_error||`Cache DNS : ${when(lists.dns_updated)}`;$('list-items').replaceChildren();for(const l of lists.lists){const item=document.createElement('section');item.className='list-item';item.append(icon('database'));const head=document.createElement('label');head.className='list-head';const check=document.createElement('input');check.type='checkbox';check.checked=l.enabled;check.setAttribute('aria-label',l.name);check.onchange=async()=>{try{await post(`/api/lists/toggle?id=${encodeURIComponent(l.id)}&enabled=${check.checked}`);$('lists-status').textContent='Préférence enregistrée pour les nouvelles observations.';}catch(e){check.checked=!check.checked;$('lists-status').textContent=e.message;}};head.append(text('strong',l.name),check);item.append(head,text('p',`${l.count.toLocaleString('fr-FR')} entrées · Mise à jour : ${when(l.updated)}${l.stale?' · À actualiser':''}`));const a=text('a','Voir la source');a.href=l.url;a.target='_blank';a.rel='noreferrer';item.append(a);if(l.error)item.append(text('p',l.error));if(l.copyright){const c=text('p',l.copyright);c.className='copyright';item.append(c);}$('list-items').append(item);}$('lists-status').textContent=lists.updating?'Téléchargement en cours…':'Comparaison locale, sans transmission de vos destinations.';}catch(e){$('lists-status').textContent=e.message;}}
$('lists-button').onclick=()=>{$('lists-dialog').showModal();$('lists-button').setAttribute('aria-expanded','true');loadLists();};$('close-lists').onclick=()=>$('lists-dialog').close();$('lists-dialog').onclose=()=>$('lists-button').setAttribute('aria-expanded','false');$('refresh-lists').onclick=async()=>{try{await post('/api/lists/refresh');$('lists-status').textContent='Actualisation demandée (une heure minimum entre téléchargements).';}catch(e){$('lists-status').textContent=e.message;}};
let stopped=false;$('stop').onclick=async()=>{try{await post('/api/shutdown');stopped=true;$('status').textContent='Atlas arrêté';$('stop').disabled=true;}catch(e){$('error').hidden=false;$('error').textContent=e.message;}};
new ResizeObserver(()=>map.invalidateSize()).observe($('map'));refresh();loadLists();loadIcons();setInterval(()=>{if(!stopped)refresh();},3000);setInterval(()=>{if(!stopped)loadIcons();},10000);setInterval(()=>{if(!stopped&&$('lists-dialog').open)loadLists();},5000);
