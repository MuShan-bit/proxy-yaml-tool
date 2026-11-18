'use strict';

const $ = id => document.getElementById(id);
const state = {token:'', source:'links', result:null, busy:false, undo:null, qr:null, qrVersion:0};
function message(id, value) { $(id).textContent = value || ''; $(id).hidden = !value; }
async function api(path, body) {
  const response = await fetch(path, {method:body === undefined ? 'GET' : 'POST', headers:{'Content-Type':'application/json','X-App-Token':state.token}, body:body === undefined ? undefined : JSON.stringify(body)});
  let data;
  try { data = await response.json(); } catch { throw new Error('服务没有返回有效结果，请检查工具是否仍在运行。'); }
  if (!response.ok) throw new Error(data.error || '操作失败');
  return data;
}
function dirty() { return Boolean(state.result?.nodes.some(node => node.name !== node.savedName)); }
function clearUndo() { state.undo = null; $('undo-delete').hidden = true; }
function controls() {
  $('convert').disabled = state.busy || !state.token || dirty();
  $('save-names').disabled = state.busy || !dirty();
  $('undo-delete').disabled = state.busy || !state.undo;
  for (const id of ['copy-subscription','copy-links','download-subscription']) $(id).disabled = state.busy || !state.result || dirty();
  for (const element of document.querySelectorAll('.node-name-input,.delete-node')) element.disabled = state.busy;
  for (const element of document.querySelectorAll('.v2ray-share-action')) element.disabled = state.busy || dirty();
}
async function operation(action) {
  if (state.busy) return;
  state.busy = true;
  const saved = [...document.querySelectorAll('button,input,textarea')].map(element => [element,element.disabled]);
  saved.forEach(([element]) => { element.disabled = true; });
  $('workspace').setAttribute('aria-busy', 'true');
  message('convert-error', '');
  try { await action(); }
  catch (error) { message('convert-error', error.message); $('copy-status').textContent = '操作失败，已保留上一次订阅。'; }
  finally {
    saved.forEach(([element,disabled]) => { element.disabled = disabled; });
    state.busy = false;
    $('workspace').removeAttribute('aria-busy');
    controls();
  }
}
function renderNodes() {
  const query = $('node-search').value.trim().toLowerCase();
  const container = $('result-nodes'); container.replaceChildren();
  const nodes = state.result?.nodes || [];
  let count = 0;
  nodes.forEach((node,index) => {
    if (query && !`${node.name} ${node.server} ${node.port} ${node.protocol}`.toLowerCase().includes(query)) return;
    count++;
    const row = document.createElement('article'); row.className = 'v2ray-node';
    const label = document.createElement('label'); label.className = 'sr-only'; label.htmlFor = `node-name-${index}`; label.textContent = `节点 ${index+1} 名称`;
    const input = document.createElement('input'); input.id = label.htmlFor; input.className = 'node-name-input'; input.type = 'text'; input.value = node.name;
    input.addEventListener('input', () => {
      node.name = input.value; clearUndo(); controls();
      $('copy-status').textContent = dirty() ? '名称尚未保存，请点击“保存名称”后再导入、复制或显示二维码。' : '名称与已保存配置一致。';
    });
    const badges = document.createElement('div'); badges.className = 'v2ray-badges';
    for (const [value,style] of [[node.protocol,'protocol-pill'],[node.transport,'transport-pill']]) {
      const badge = document.createElement('span'); badge.className = style; badge.textContent = value.toUpperCase(); badges.append(badge);
    }
    const address = document.createElement('div'); address.className = 'server-address'; address.textContent = `${node.server.includes(':')?'['+node.server+']':node.server}:${node.port}`;
    const actions = document.createElement('div'); actions.className = 'v2ray-node-actions';
    const action = (text,style,handler) => {
      const button = document.createElement('button'); button.type = 'button'; button.className = style; button.textContent = text; button.title = `${text}：${node.savedName}`; button.setAttribute('aria-label', `${text}：${node.savedName}`); button.addEventListener('click', handler); actions.append(button);
    };
    action('复制链接','button secondary v2ray-share-action', () => copyText(node.link));
    action('二维码','button secondary v2ray-share-action', () => showQR(node));
    action('删除','delete-node', () => removeNode(index));
    row.append(label,input,badges,address,actions); container.append(row);
  });
  $('no-search-results').hidden = count > 0 || !state.result;
  $('no-search-results').textContent = nodes.length ? '没有匹配的节点。' : '暂无节点，可从左侧继续导入。';
  controls();
}
function renderResult(result, status) {
  state.result = result;
  result.nodes.forEach(node => { if (node.savedName === undefined) node.savedName = node.name; });
  for (const key of ['added','skipped','total']) $('metric-'+key).textContent = result[key];
  $('subscription-card').hidden = false;
  $('subscription-url').value = result.subscriptionURL;
  $('links-output').value = result.content;
  $('output-empty').hidden = true; $('nodes-view').hidden = false;
  $('result-state').textContent = status; $('result-state').classList.add('ready');
  const warnings = $('result-warnings'); warnings.replaceChildren(); warnings.hidden = !result.warnings.length;
  if (result.warnings.length) {
    const list = document.createElement('ul');
    for (const warning of result.warnings) { const item = document.createElement('li'); item.textContent = warning; list.append(item); }
    warnings.append(list);
  }
  renderNodes();
}
const tabs = [...document.querySelectorAll('[data-source]')];
tabs.forEach((button,index) => {
  button.addEventListener('click', () => {
    state.source = button.dataset.source;
    tabs.forEach(tab => { const active = tab === button; tab.classList.toggle('active',active); tab.setAttribute('aria-selected',String(active)); tab.tabIndex = active ? 0 : -1; });
    $('links-panel').hidden = state.source !== 'links'; $('nodes-panel').hidden = state.source !== 'yaml';
    clearUndo();
  });
  button.addEventListener('keydown', event => {
    if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length-1 : (index+1)%tabs.length;
    tabs[next].click(); tabs[next].focus();
  });
});
for (const kind of ['links','nodes']) {
  $(kind+'-input').addEventListener('input', clearUndo);
  $(kind+'-upload-button').addEventListener('click', () => $(kind+'-upload').click());
  $(kind+'-upload').addEventListener('change', event => {
    const file = event.target.files?.[0]; if (!file) return;
    operation(async () => {
      if (file.size > 3<<20) throw new Error('请选择小于 3 MB 的文件。');
      $(kind+'-input').value = await file.text(); clearUndo();
    });
    event.target.value = '';
  });
}
$('node-search').addEventListener('input', renderNodes);
$('convert').addEventListener('click', () => operation(async () => {
  if (dirty()) throw new Error('请先保存节点名称。');
  const inputID = state.source === 'links' ? 'links-input' : 'nodes-input';
  if (!$(inputID).value.trim()) throw new Error('请先粘贴或上传需要导入的节点。');
  $('convert').querySelector('span').textContent = '正在转换…';
  try {
    const result = await api('/api/v2ray/convert', {links:state.source === 'links' ? $(inputID).value : '', nodesYaml:state.source === 'yaml' ? $(inputID).value : '', existing:state.result?.nodes.map(node => node.link) || []});
    clearUndo(); $(inputID).value = '';
    renderResult(result,'订阅已生成');
    $('convert-status').textContent = `新增 ${result.added} 个，跳过重复 ${result.skipped} 个；当前共 ${result.total} 个节点。`;
    $('copy-status').textContent = '订阅已更新，可复制地址、分享链接或显示二维码。';
    if (innerWidth <= 760) $('output-heading').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth',block:'start'});
  } finally { $('convert').querySelector('span').textContent = '导入并生成订阅'; }
}));
$('save-names').addEventListener('click', () => operation(async () => {
  const result = await api('/api/v2ray/edit', {links:state.result.nodes.map(node => node.link), names:state.result.nodes.map(node => node.name)});
  result.added = state.result.added; result.skipped = state.result.skipped;
  clearUndo(); renderResult(result,'名称已保存');
  $('copy-status').textContent = '名称已保存，订阅、分享链接与二维码已同步。';
}));
async function removeNode(index) {
  await operation(async () => {
    const snapshot = structuredClone(state.result);
    const result = await api('/api/v2ray/edit', {links:state.result.nodes.map(node => node.link), deleteIndex:index});
    const survivors = state.result.nodes.filter((_,i) => i !== index);
    result.nodes.forEach((node,i) => { node.savedName = node.name; node.name = survivors[i].name; });
    result.added = snapshot.added; result.skipped = snapshot.skipped;
    renderResult(result,'节点已删除');
    state.undo = snapshot; $('undo-delete').hidden = false;
    $('copy-status').textContent = `已删除“${snapshot.nodes[index].savedName}”，订阅已更新。` + (dirty()?' 其余名称修改仍待保存。':'');
  });
  if (state.undo) $('undo-delete').focus();
}
$('undo-delete').addEventListener('click', async () => {
  if (!state.undo) return;
  await operation(async () => {
    const snapshot = state.undo;
    const restored = await api('/api/v2ray/edit', {links:snapshot.nodes.map(node => node.link)});
    snapshot.content = restored.content; snapshot.subscription = restored.subscription; snapshot.subscriptionURL = restored.subscriptionURL;
    clearUndo(); renderResult(snapshot,'已撤销删除');
    $('copy-status').textContent = '已恢复上一次删除，订阅已更新。' + (dirty()?' 名称修改仍待保存。':'');
  });
  $('node-search').focus();
});
async function copyText(value, statusID = 'copy-status', fallback = 'manual-copy') {
  try { await navigator.clipboard.writeText(value); $(statusID).textContent = '已复制到剪贴板。'; }
  catch {
    const input = $(fallback); input.value = value;
    if (fallback === 'qr-link') $('qr-link-details').open = true;
    else $('manual-copy-panel').hidden = false;
    input.focus(); input.select(); $(statusID).textContent = '请使用 Ctrl+C / ⌘C 复制选中的内容。';
  }
}
$('copy-subscription').addEventListener('click', () => copyText($('subscription-url').value));
$('copy-links').addEventListener('click', () => copyText(state.result.content));
function downloadURL(url,name) { const link = document.createElement('a'); link.href = url; link.download = name; link.click(); }
$('download-subscription').addEventListener('click', () => {
  const url = URL.createObjectURL(new Blob([state.result.subscription], {type:'text/plain;charset=utf-8'}));
  downloadURL(url,'v2ray-subscription.txt'); setTimeout(() => URL.revokeObjectURL(url),1000);
  $('copy-status').textContent = '已下载 Base64 订阅；下次可直接重新导入。';
});
async function showQR(node) {
  if (dirty() || state.busy) return;
  const version = ++state.qrVersion;
  state.qr = {node,url:null};
  $('qr-name').textContent = node.name; $('qr-link').value = node.link; $('qr-link-details').open = false;
  $('qr-image').hidden = true; $('qr-loading').hidden = false; $('qr-download').disabled = true;
  message('qr-error',''); $('qr-status').textContent = '';
  $('qr-dialog').showModal();
  try {
    const response = await fetch('/api/v2ray/qrcode', {method:'POST',headers:{'Content-Type':'application/json','X-App-Token':state.token},body:JSON.stringify({link:node.link})});
    if (!response.ok) { const error = await response.json(); throw new Error(error.error || '二维码生成失败'); }
    const blob = await response.blob();
    const dataURL = await new Promise((resolve,reject) => { const reader = new FileReader(); reader.onload = () => resolve(reader.result); reader.onerror = () => reject(new Error('二维码图片读取失败')); reader.readAsDataURL(blob); });
    if (version !== state.qrVersion) return;
    state.qr.url = URL.createObjectURL(blob);
    $('qr-image').src = dataURL; $('qr-image').hidden = false; $('qr-download').disabled = false;
  } catch (error) { if (version === state.qrVersion) message('qr-error',error.message); }
  finally { if (version === state.qrVersion) $('qr-loading').hidden = true; }
}
$('qr-close').addEventListener('click', () => $('qr-dialog').close());
$('qr-dialog').addEventListener('close', () => {
  state.qrVersion++;
  if (state.qr?.url) URL.revokeObjectURL(state.qr.url);
  state.qr = null; $('qr-image').removeAttribute('src'); $('qr-link').value = '';
});
$('qr-copy').addEventListener('click', () => copyText(state.qr.node.link,'qr-status','qr-link'));
$('qr-download').addEventListener('click', () => {
  if (!state.qr?.url) return;
  downloadURL(state.qr.url,'v2ray-node.png'); $('qr-status').textContent = '已下载节点二维码。';
});
controls();
(async () => {
  await operation(async () => {
    state.token = (await api('/api/session')).token;
    const current = await api('/api/v2ray/current');
    if (current.nodes) { renderResult(current,'已恢复订阅'); $('copy-status').textContent = '已载入当前服务中保存的 v2rayN 订阅。'; }
  });
})();
