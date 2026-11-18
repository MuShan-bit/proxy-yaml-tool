'use strict';

const $ = id => document.getElementById(id);
const state = {token:'', source:'links', result:null, view:'nodes', version:0};

function showMessage(id, message) {
  const element = $(id);
  element.textContent = message || '';
  element.hidden = !message;
}
function warnings(id, messages) {
  const element = $(id);
  element.replaceChildren();
  element.hidden = !messages?.length;
  if (!messages?.length) return;
  const list = document.createElement('ul');
  for (const message of messages) { const item = document.createElement('li'); item.textContent = message; list.append(item); }
  element.append(list);
}
async function api(path, body) {
  const response = await fetch(path, {method: body === undefined ? 'GET' : 'POST', headers:{'Content-Type':'application/json','X-App-Token':state.token}, body: body === undefined ? undefined : JSON.stringify(body)});
  let data;
  try { data = await response.json(); } catch { throw new Error('服务没有返回有效结果，请检查工具是否仍在运行。'); }
  if (!response.ok) { const error = new Error(data.error || '操作失败'); error.data = data; throw error; }
  return data;
}
function invalidate() {
  state.version++;
  if (state.result) {
    state.result = null;
    document.querySelector('.output-panel').classList.add('stale');
    $('result-state').textContent = '输入已变化';
    $('result-state').classList.remove('ready');
  }
  $('copy-yaml').disabled = $('download-yaml').disabled = $('save-names').disabled = true;
  for (const input of document.querySelectorAll('.node-name-input')) input.disabled = true;
  $('subscription-card').hidden = true;
  $('copy-status').textContent = '转换后可复制、下载或订阅';
}
function switchTabs(buttons, active, attr) {
  for (const button of buttons) {
    const selected = button.dataset[attr] === active;
    button.classList.toggle('active', selected);
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
  }
}
function keyboardTabs(buttons) {
  for (const button of buttons) button.addEventListener('keydown', event => {
    if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    event.preventDefault();
    const index = buttons.indexOf(button);
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + buttons.length) % buttons.length;
    buttons[next].click(); buttons[next].focus();
  });
}
const sourceTabs = [...document.querySelectorAll('[data-source]')];
sourceTabs.forEach(button => button.addEventListener('click', () => {
  state.source = button.dataset.source;
  switchTabs(sourceTabs, state.source, 'source');
  $('links-panel').hidden = state.source !== 'links';
  $('nodes-panel-source').hidden = state.source !== 'nodes';
  invalidate();
}));
keyboardTabs(sourceTabs);
const resultTabs = [...document.querySelectorAll('[data-result]')];
function selectResultView(view) {
  state.view = view;
  switchTabs(resultTabs, view, 'result');
  const hasOutput = Boolean($('yaml-output').value);
  $('nodes-view').hidden = !hasOutput || view !== 'nodes';
  $('yaml-view').hidden = !hasOutput || view !== 'yaml';
}
resultTabs.forEach(button => button.addEventListener('click', () => selectResultView(button.dataset.result)));
keyboardTabs(resultTabs);

async function loadTemplate(blank = false) {
  showMessage('app-error', '');
  try {
    const data = await api('/api/template' + (blank ? '?blank=1' : ''));
    $('template-input').value = data.yaml;
    $('template-name').textContent = data.name;
    $('template-name').title = data.name;
    invalidate();
    if (data.warning) showMessage('app-error', data.warning);
  } catch (error) { showMessage('app-error', error.message); }
}
$('reload-template').addEventListener('click', () => loadTemplate());
$('blank-template').addEventListener('click', () => loadTemplate(true));
function upload(buttonId, inputId, targetId, maxBytes, onLoad) {
  $(buttonId).addEventListener('click', () => $(inputId).click());
  $(inputId).addEventListener('change', async event => {
    const file = event.target.files?.[0]; if (!file) return;
    try {
      if (file.size > maxBytes) throw new Error('文件过大，请选择小于 ' + Math.round(maxBytes / 1024) + ' KB 的文件。');
      $(targetId).value = await file.text();
      invalidate();
      if (onLoad) onLoad(file);
    } catch (error) { showMessage('app-error', error.message); }
    event.target.value = '';
  });
}
upload('template-upload-button', 'template-upload', 'template-input', 3 << 20, file => { $('template-name').textContent = file.name; $('template-name').title = file.name; });
upload('links-upload-button', 'links-upload', 'links-input', 1 << 20);
upload('nodes-upload-button', 'nodes-upload', 'nodes-input', 3 << 20);
for (const id of ['template-input','links-input','nodes-input','replacement-ips','clean-existing','sync-groups','country','mark-existing']) $(id).addEventListener('input', invalidate);
$('country').addEventListener('change', () => { $('mark-existing').disabled = !$('country').checked; });

function renderResultNodes() {
  const query = $('node-search').value.trim().toLowerCase();
  const nodes = state.result?.nodes || [];
  const container = $('result-nodes'); container.replaceChildren();
  let count = 0;
  for (let index = 0; index < nodes.length; index++) {
    const node = nodes[index];
    if (query && !`${node.name} ${node.server} ${node.protocol} ${node.port}`.toLowerCase().includes(query)) continue;
    count++;
    const row = document.createElement('tr');
    const nameCell = document.createElement('td');
    const name = document.createElement('input'); name.className = 'node-name-input'; name.type = 'text'; name.value = node.name; name.dataset.index = String(index); name.setAttribute('aria-label', `节点 ${index + 1} 名称`);
    name.addEventListener('input', () => {
      node.name = name.value;
      $('save-names').disabled = false;
      $('copy-yaml').disabled = $('download-yaml').disabled = $('copy-subscription').disabled = true;
      $('copy-status').textContent = '名称尚未保存，请点击“保存名称”更新订阅';
    });
    const address = document.createElement('div'); address.className = 'server-address'; address.textContent = `${node.server.includes(':') ? '[' + node.server + ']' : node.server}:${node.port}`;
    nameCell.append(name, address);
    const protocolCell = document.createElement('td'); const protocol = document.createElement('span'); protocol.className = 'protocol-pill'; protocol.textContent = node.protocol.toUpperCase(); protocolCell.append(protocol);
    const transportCell = document.createElement('td'); const transport = document.createElement('span'); transport.className = 'transport-pill' + (node.transport.includes('udp') ? ' udp' : ''); transport.textContent = node.transport.toUpperCase(); transportCell.append(transport);
    row.append(nameCell, protocolCell, transportCell); container.append(row);
  }
  $('no-search-results').hidden = count > 0 || !state.result;
}
$('node-search').addEventListener('input', renderResultNodes);

async function convert() {
  showMessage('convert-error', '');
  if (!$('template-input').value.trim()) { showMessage('convert-error', '请先加载或粘贴 YAML 模板。'); return; }
  const version = state.version;
  const payload = {template:$('template-input').value, links:state.source === 'links' ? $('links-input').value : '', nodesYaml:state.source === 'nodes' ? $('nodes-input').value : '', servers:$('replacement-ips').value.trim(), options:{cleanExisting:$('clean-existing').checked, syncGroups:$('sync-groups').checked, country:$('country').checked, markExisting:$('mark-existing').checked}};
  $('convert').disabled = true; $('convert').setAttribute('aria-busy', 'true'); $('convert').querySelector('span').textContent = '正在转换…';
  $('convert-status').textContent = payload.options.country ? '正在去重并查询 IP 归属地…' : '正在合并节点与代理组…';
  try {
    const result = await api('/api/convert', payload);
    if (version !== state.version) return;
    state.result = result;
    $('template-input').value = result.yaml;
    $('template-name').textContent = '当前配置';
    $('template-name').title = '继续导入会合并到当前配置；加载模板可重新开始';
    document.querySelector('.output-panel').classList.remove('stale');
    for (const key of ['added','skipped','removed','total']) $('metric-' + key).textContent = result[key];
    $('yaml-output').value = result.yaml;
    $('output-empty').hidden = true;
    $('result-state').textContent = '转换完成'; $('result-state').classList.add('ready');
    $('group-count').textContent = `${result.groups} 个代理组`;
    $('subscription-url').value = result.subscriptionURL || '';
    $('subscription-card').hidden = !result.subscriptionURL;
    renderResultNodes(); selectResultView(state.view); warnings('result-warnings', result.warnings);
    $('copy-yaml').disabled = $('download-yaml').disabled = $('copy-subscription').disabled = false;
    $('save-names').disabled = true;
    $('convert-status').textContent = `转换完成：新增 ${result.added}，跳过重复 ${result.skipped}，清理重复 ${result.removed}。` + (result.unsupported ? ` 已跳过 ${result.unsupported} 个不兼容节点，详见结果提示。` : '');
    $('copy-status').textContent = '已生成配置，原模板保持不变';
    if (innerWidth <= 760) $('output-heading').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block:'start'});
  } catch (error) { showMessage('convert-error', error.message); $('convert-status').textContent = '转换失败，请检查输入。'; }
  finally { $('convert').disabled = false; $('convert').removeAttribute('aria-busy'); $('convert').querySelector('span').textContent = '转换并生成订阅'; }
}
$('convert').addEventListener('click', convert);
$('save-names').addEventListener('click', async () => {
  if (!state.result) return;
  const result = state.result;
  const names = result.nodes.map(node => node.name.trim());
  showMessage('convert-error', '');
  $('save-names').disabled = true;
  for (const input of document.querySelectorAll('.node-name-input')) input.disabled = true;
  try {
    const data = await api('/api/rename', {yaml:result.yaml, names});
    if (state.result !== result) return;
    result.yaml = data.yaml;
    result.subscriptionURL = data.subscriptionURL;
    result.nodes.forEach((node, index) => { node.name = names[index]; });
    $('yaml-output').value = data.yaml;
    $('template-input').value = data.yaml;
    $('copy-yaml').disabled = $('download-yaml').disabled = $('copy-subscription').disabled = false;
    renderResultNodes();
    $('copy-status').textContent = '节点名称已保存，引用已同步';
  } catch (error) {
    if (state.result !== result) return;
    $('copy-status').textContent = error.message;
    $('save-names').disabled = false;
  } finally {
    if (state.result === result) for (const input of document.querySelectorAll('.node-name-input')) input.disabled = false;
  }
});
$('copy-subscription').addEventListener('click', async () => {
  const value = $('subscription-url').value; if (!value) return;
  try { await navigator.clipboard.writeText(value); $('copy-status').textContent = '订阅地址已复制'; }
  catch { $('subscription-url').focus(); $('subscription-url').select(); $('copy-status').textContent = '请使用 Ctrl+C / ⌘C 复制选中的地址'; }
});
$('copy-yaml').addEventListener('click', async () => {
  if (!state.result) return;
  try { await navigator.clipboard.writeText(state.result.yaml); $('copy-status').textContent = 'YAML 已复制到剪贴板'; }
  catch { selectResultView('yaml'); $('yaml-output').focus(); $('yaml-output').select(); $('copy-status').textContent = '请使用 Ctrl+C / ⌘C 复制选中的 YAML'; }
});
$('download-yaml').addEventListener('click', () => {
  if (!state.result) return;
  const url = URL.createObjectURL(new Blob([state.result.yaml], {type:'application/yaml;charset=utf-8'}));
  const link = document.createElement('a'); link.href = url; link.download = 'mihomo-config.yaml'; link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000); $('copy-status').textContent = '已下载 mihomo-config.yaml';
});
(async () => {
  try { const session = await api('/api/session'); state.token = session.token; await loadTemplate(); }
  catch (error) { showMessage('app-error', error.message); }
})();
