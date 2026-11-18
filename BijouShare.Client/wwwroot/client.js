'use strict';
const $ = selector => document.querySelector(selector);
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
let state, csrf = '', busy = false, selectedRemoval = null, toastTimer;
let stateSequence = 0, polling = false, activeView = '', letterSignature, pendingSignature;
const driveViews = new Map();
const accessKey = 'bijoushare.managementAccess';
const launch = new URLSearchParams(location.hash.slice(1));
if (launch.has('access')) {
  sessionStorage.setItem(accessKey, launch.get('access'));
  history.replaceState(null, '', location.pathname + location.search);
}
const descriptions = {
  PendingApproval: ['Awaiting approval', 'An administrator must approve this device and choose its groups.', 'waiting'],
  DeviceRejected: ['Blocked', 'An administrator must explicitly approve this device before it can connect.', 'blocked'],
  DeviceBlocked: ['Blocked', 'An administrator must enable this device before it can connect.', 'blocked'],
  InvalidInvite: ['Invite unavailable', 'The invite is invalid, expired, revoked, or has no uses remaining. Ask for a new link.', 'blocked'],
  InviteInvalid: ['Invite unavailable', 'The invite is invalid, expired, revoked, or has no uses remaining. Ask for a new link.', 'blocked'],
  InviteExpired: ['Invite expired', 'Ask the server administrator for a new invitation.', 'blocked'],
  InviteExhausted: ['Invite used up', 'Ask the server administrator for a new invitation.', 'blocked'],
  ServerIdentityChanged: ['Fingerprint mismatch', 'Check the address and full fingerprint with the administrator. To trust an intentional identity change, disconnect this entry and add the verified link.', 'blocked'],
  ServerIdentityConflict: ['Server identity conflict', 'A shortened folder ID conflicts with another server. Access remains blocked.', 'blocked'],
  ServerUpgradeRequired: ['Server update required', 'This server needs an update before it can appear on the drive.', 'blocked'],
  AuthenticationFailed: ['Authentication failed', 'The server could not prove its identity. Check the endpoint with its administrator.', 'blocked'],
  HybridUnavailable: ['Windows update required', 'This connection requires native Windows support for ML-KEM-768 and SHA3-256.', 'blocked'],
  ConfigurationError: ['Configuration error', 'The client could not access or save its configuration. Check the service account and data directory.', 'blocked'],
  Disconnected: ['Offline', 'Its drive folder is temporarily hidden. Retrying automatically; other connected servers stay available.', ''],
  Waiting: ['Connecting', 'Waiting for an authenticated connection.', 'waiting']
};

async function api(path, method = 'GET', body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch('/api' + path, {method, credentials:'same-origin', signal:controller.signal,
      headers:{'Content-Type':'application/json','X-CSRF-TOKEN':csrf, Authorization:'Bearer ' + (sessionStorage.getItem(accessKey) || '')}, body:body === undefined ? undefined : JSON.stringify(body)});
    if (response.status === 403 || response.status === 401) throw new Error('Click the BijouShare Client tray icon in your Windows session to manage your drives.');
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status}). Refresh and try again.`);
    return result;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('The client did not respond in time. Refresh before retrying.');
    if (error instanceof TypeError) throw new Error('Cannot reach the client service. Start BijouShare on this computer, then refresh.');
    throw error;
  } finally { clearTimeout(timer); }
}
function validateName(input) {
  input.setCustomValidity(input.value !== input.value.trim() || /[\u0000-\u001f\u007f]/.test(input.value) ? 'Use a name without surrounding whitespace or control characters.' : '');
  return input.reportValidity();
}

function newDriveView(mountPoint) {
  const id = 'drive-' + mountPoint[0].toUpperCase();
  const tab = document.createElement('button');
  tab.type = 'button';
  tab.id = 'tab-' + id;
  tab.setAttribute('role', 'tab');
  tab.setAttribute('aria-controls', id);
  const title = 'Drive ' + mountPoint.slice(0, 2);
  tab.setAttribute('aria-label', title);
  const icon = document.createElement('span');
  icon.className = 'bi bi-drives';
  icon.setAttribute('aria-hidden', 'true');
  const label = document.createElement('span');
  const prefix = document.createElement('span');
  prefix.className = 'tab-drive-prefix';
  prefix.textContent = 'Drive ';
  label.append(prefix, mountPoint.slice(0, 2));
  tab.append(icon, label);
  $('#drive-tabs').append(tab);

  const panel = $('#drive-template').content.firstElementChild.cloneNode(true);
  panel.id = id;
  panel.dataset.mountPoint = mountPoint;
  panel.setAttribute('aria-labelledby', tab.id);
  panel.querySelector('.drive-title').textContent = title;
  const remove = panel.querySelector('.remove-drive');
  remove.setAttribute('aria-label', 'Remove drive ' + mountPoint.slice(0, 2));
  panel.querySelector('.remove-help').id = id + '-remove-help';
  remove.setAttribute('aria-describedby', id + '-remove-help');
  $('#drive-panels').append(panel);
  return {tab, panel, signature:''};
}

function selectView(id, remember = true) {
  activeView = id;
  for (const tab of $('#sidebar-tabs').querySelectorAll('[role="tab"]')) {
    const panelId = tab.getAttribute('aria-controls');
    const selected = panelId === id;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
    document.getElementById(panelId).hidden = !selected;
    if (selected) $('#view-name').textContent = tab.textContent.trim();
  }
  $('#refresh').hidden = !id.startsWith('drive-');
  if (remember) history.replaceState(null, '', '#' + id);
}

function renderDrive(view, drive, servers) {
  const panel = view.panel;
  const signature = JSON.stringify([drive, servers, state.mountPoint, state.drives.length]);
  if (signature === view.signature) return;
  view.signature = signature;
  panel.querySelector('.drive-status').textContent = drive.error ? 'Mount needs attention' : drive.mounted ? 'Mounted in File Explorer' : 'Mounting…';
  panel.querySelector('.mount-icon').className = 'mount-icon bi bi-' + (drive.error ? 'alert' : drive.mounted ? 'check' : 'clock');
  const notice = panel.querySelector('.drive-notice');
  notice.hidden = !drive.error;
  notice.textContent = drive.error || '';
  const connected = servers.filter(server => server.connected).length;
  panel.querySelector('.count').textContent = connected + (connected === 1 ? ' server connected' : ' servers connected');
  panel.querySelector('.server-total').textContent = String(servers.length);
  const linkTarget = panel.querySelector('.link-target');
  linkTarget.hidden = state.drives.length < 2;
  linkTarget.textContent = state.drives.length < 2 ? '' : 'Opening a wad:// link outside this page adds its server to drive ' + state.mountPoint.slice(0, 2) + '.';
  panel.querySelector('.remove-drive').disabled = servers.length > 0;
  panel.querySelector('.remove-help').textContent = servers.length ? 'Disconnect the servers on this drive before removing it.' : '';
  const list = panel.querySelector('.server-list');
  const openDetails = new Set([...list.querySelectorAll('.server-card details[open]')].map(details => {
    const card = details.closest('.server-card'); return `${card.dataset.host}\n${card.dataset.port}`;
  }));
  const actions = ['[data-remove]', 'summary'];
  const focusedControl = list.contains(document.activeElement) ? document.activeElement.closest(actions.join(',')) : null;
  const focusedCard = focusedControl?.closest('.server-card');
  const focusedKey = focusedCard ? `${focusedCard.dataset.host}\n${focusedCard.dataset.port}` : null;
  const focusSelector = actions.find(selector => focusedControl?.matches(selector));
  list.innerHTML = servers.length ? servers.map(server => {
    const [label, detail, style] = server.connected
      ? ['Connected', '', 'connected']
      : (descriptions[server.error] || descriptions.Waiting);
    const endpointAttributes = `data-host="${escapeHtml(server.host)}" data-port="${server.port}"`;
    const folder = server.folderName ? `<p class="folder"><span class="bi bi-folder" aria-hidden="true"></span><code>${escapeHtml(drive.mountPoint)}${escapeHtml(server.folderName)}\\</code>${server.connected ? '' : '<span class="folder-note">Available when connected</span>'}</p>` : '';
    const trustDetails = server.trustedServerId ? `<details${openDetails.has(`${server.host}\n${server.port}`) ? ' open' : ''}><summary>${server.connected ? 'Verified server fingerprint' : 'Server fingerprint from link'}</summary><p class="server-digest">${escapeHtml(server.trustedServerId)}</p></details>` : '';
    const icon = {connected:'check', waiting:'clock', blocked:'alert'}[style] || 'network';
    return `<article class="server-card" ${endpointAttributes}>
      <span class="server-icon"><span class="bi bi-server" aria-hidden="true"></span></span>
      <div class="server-identity"><h3>${escapeHtml(server.serverName || server.host)}</h3><p class="server-endpoint">${escapeHtml(server.host)}:${server.port}</p></div>
      <span class="status ${style}"><span class="bi bi-${icon}" aria-hidden="true"></span>${label}</span>
      <div class="server-info">${folder}${detail ? `<p class="server-description">${escapeHtml(detail)}</p>` : ''}
        <div class="server-actions">${trustDetails}<button type="button" data-remove ${endpointAttributes} aria-label="Disconnect ${escapeHtml(server.serverName || server.host)}">Disconnect</button></div>
      </div></article>`;
  }).join('') : '<div class="empty"><span class="tile"><span class="bi bi-server" aria-hidden="true"></span></span><div><strong>No servers on this drive</strong><p>Connect a server to see its folders in File Explorer.</p></div></div>';
  if (focusedKey) [...list.querySelectorAll('.server-card')]
    .find(card => `${card.dataset.host}\n${card.dataset.port}` === focusedKey)?.querySelector(focusSelector)?.focus({preventScroll:true});
}

function renderAddDrive() {
  const available = state.availableDriveLetters;
  const select = $('#new-letter');
  const signature = JSON.stringify(available);
  if (signature !== letterSignature) {
    letterSignature = signature;
    const chosen = select.value;
    select.replaceChildren(...available.map(letter => new Option(letter, letter)));
    if (available.includes(chosen)) select.value = chosen;
  }
  select.disabled = !available.length;
  $('#add-drive-button').disabled = !available.length;
  $('#letter-help').hidden = available.length > 0;
  $('#add-title').textContent = state.drives.length ? 'Add a drive' : 'Add your first drive';

  const pending = state.servers.filter(server => !server.mountPoint);
  $('#pending').hidden = !pending.length;
  const endpoints = JSON.stringify(pending.map(({host, port}) => [host, port]));
  if (endpoints === pendingSignature) return;
  pendingSignature = endpoints;
  $('#pending-list').replaceChildren(...pending.map(server => {
    const row = document.createElement('li');
    const label = document.createElement('span');
    label.textContent = server.host + ':' + server.port;
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = 'Remove';
    button.setAttribute('aria-label', 'Remove queued server ' + label.textContent);
    button.dataset.host = server.host;
    button.dataset.port = server.port;
    row.append(label, button);
    return row;
  }));
}

function render(next) {
  const previous = state;
  state = next;
  $('#loading').hidden = true;
  $('#service-notice').hidden = true;
  $('#setup').hidden = state.setupComplete;
  $('#dashboard').hidden = !state.setupComplete;
  if (!state.setupComplete) {
    if (!previous || previous.setupComplete) {
      $('#setup-name').value = state.deviceName;
      $('#setup-name').focus();
    }
    return;
  }
  $('#sidebar-name').textContent = state.deviceName;
  $('#device-id').textContent = state.deviceId;
  document.title = state.deviceName + ' · BijouShare';
  if (!previous?.setupComplete || $('#device-name').value === previous.deviceName)
    $('#device-name').value = state.deviceName;

  for (const [letter, view] of driveViews) {
    if (state.drives.some(drive => drive.mountPoint === letter)) continue;
    view.tab.remove();
    view.panel.remove();
    driveViews.delete(letter);
  }
  for (const drive of state.drives) {
    if (!driveViews.has(drive.mountPoint)) driveViews.set(drive.mountPoint, newDriveView(drive.mountPoint));
    renderDrive(driveViews.get(drive.mountPoint), drive, state.servers.filter(server => server.mountPoint === drive.mountPoint));
  }

  renderAddDrive();
  const preferred = activeView || location.hash.slice(1);
  const preferredTab = document.getElementById('tab-' + preferred);
  const fallback = driveViews.values().next().value?.panel.id || 'add';
  selectView(preferredTab?.getAttribute('role') === 'tab' ? preferred : fallback, false);
}

async function reload() {
  const sequence = ++stateSequence;
  const next = await api('/state');
  if (sequence === stateSequence) render(next);
}
function toast(message) {
  clearTimeout(toastTimer);
  $('#toast').textContent = message;
  $('#toast').hidden = false;
  toastTimer = setTimeout(() => {$('#toast').hidden = true;}, 5500);
}
async function submit(button, errorElement, operation) {
  if (busy) return;
  busy = true;
  stateSequence++;
  button.disabled = true;
  errorElement.textContent = '';
  try {await operation();}
  catch (error) {errorElement.textContent = error.message;}
  finally {
    button.disabled = false;
    if (state?.setupComplete) $('#add-drive-button').disabled = !state.availableDriveLetters.length;
    busy = false;
  }
}

const narrowLayout = window.matchMedia('(max-width: 700px)');
function syncTabOrientation() {
  $('#sidebar-tabs').setAttribute('aria-orientation', narrowLayout.matches ? 'horizontal' : 'vertical');
}
narrowLayout.addEventListener('change', syncTabOrientation);
syncTabOrientation();
$('#sidebar-tabs').addEventListener('click', event => {
  const tab = event.target.closest('[role="tab"]');
  if (tab) selectView(tab.getAttribute('aria-controls'));
});
$('#sidebar-tabs').addEventListener('keydown', event => {
  const tabs = [...$('#sidebar-tabs').querySelectorAll('[role="tab"]')];
  const index = tabs.indexOf(event.target);
  if (index < 0) return;
  let next;
  switch (event.key) {
    case 'ArrowDown': case 'ArrowRight': next = (index + 1) % tabs.length; break;
    case 'ArrowUp': case 'ArrowLeft': next = (index + tabs.length - 1) % tabs.length; break;
    case 'Home': next = 0; break;
    case 'End': next = tabs.length - 1; break;
    default: return;
  }
  event.preventDefault();
  selectView(tabs[next].getAttribute('aria-controls'));
  tabs[next].focus();
});

$('#setup-name').addEventListener('input', () => $('#setup-name').setCustomValidity(''));
$('#device-name').addEventListener('input', () => $('#device-name').setCustomValidity(''));
$('#copy-device-id').addEventListener('click', async () => {
  const fingerprint = $('#device-id');
  try {
    await navigator.clipboard.writeText(fingerprint.textContent);
    toast('Device fingerprint copied.');
  } catch {
    const range = document.createRange();
    range.selectNodeContents(fingerprint);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    toast('Fingerprint selected. Press Ctrl+C to copy it.');
  }
});
$('#setup-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!validateName($('#setup-name'))) return;
  await submit($('#finish-setup'), $('#setup-error'), async () => {
    render(await api('/device', 'PUT', {deviceName:$('#setup-name').value}));
    document.getElementById('tab-' + activeView).focus();
    toast('Setup complete.');
  });
});
$('#device-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!validateName($('#device-name'))) return;
  await submit(event.currentTarget.querySelector('button'), $('#device-error'), async () => {
    render(await api('/device', 'PUT', {deviceName:$('#device-name').value}));
    $('#device-name').value = state.deviceName;
    toast('Device settings saved.');
  });
});
$('#add-drive').addEventListener('submit', async event => {
  event.preventDefault();
  const mountPoint = $('#new-letter').value;
  if (!mountPoint) return;
  await submit($('#add-drive-button'), $('#drives-error'), async () => {
    render(await api('/drives', 'POST', {mountPoint}));
    const view = driveViews.get(mountPoint);
    if (view) {
      selectView(view.panel.id);
      view.tab.focus();
    }
    toast('Drive ' + mountPoint.slice(0, 2) + ' added.');
  });
});
$('#pending-list').addEventListener('click', async event => {
  const button = event.target.closest('button[data-host]');
  if (!button) return;
  await submit(button, $('#pending-error'), async () => {
    render(await api('/servers/remove', 'POST', {host:button.dataset.host, port:Number(button.dataset.port)}));
    toast('Queued server removed.');
  });
});
$('#drive-panels').addEventListener('submit', async event => {
  if (!event.target.matches('.connect-form')) return;
  event.preventDefault();
  const form = event.target;
  const panel = form.closest('.drive-panel');
  const input = form.elements.uri;
  await submit(form.querySelector('button'), form.querySelector('.server-error'), async () => {
    const uri = input.value.trim();
    render(await api('/servers', 'POST', {uri, mountPoint:panel.dataset.mountPoint}));
    form.reset();
    toast('Server saved. Its folder appears after authentication and approval.');
  });
});
$('#drive-panels').addEventListener('click', async event => {
  const panel = event.target.closest('.drive-panel');
  if (!panel) return;
  const removeDrive = event.target.closest('.remove-drive');
  if (removeDrive) {
    await submit(removeDrive, panel.querySelector('.remove-drive-error'), async () => {
      render(await api('/drives/remove', 'POST', {mountPoint:panel.dataset.mountPoint}));
      selectView(activeView);
      document.getElementById('tab-' + activeView).focus();
      toast('Drive removed.');
    });
    return;
  }
  const removeServer = event.target.closest('[data-remove]');
  if (!removeServer) return;
  selectedRemoval = {host:removeServer.dataset.host, port:Number(removeServer.dataset.port), mountPoint:panel.dataset.mountPoint};
  $('#remove-name').textContent = selectedRemoval.host + ':' + selectedRemoval.port;
  $('#remove-error').textContent = '';
  $('#remove-dialog').showModal();
  $('#cancel-remove').focus();
});
$('#cancel-remove').addEventListener('click', () => $('#remove-dialog').close());
$('#remove-dialog').addEventListener('close', () => {selectedRemoval = null;});
$('#confirm-remove').addEventListener('click', async () => {
  if (!selectedRemoval) return;
  await submit($('#confirm-remove'), $('#remove-error'), async () => {
    render(await api('/servers/remove', 'POST', selectedRemoval));
    $('#remove-dialog').close();
    toast('Server disconnected.');
  });
});
$('#refresh').addEventListener('click', async () => {
  await submit($('#refresh'), $('#refresh-error'), async () => {
    render(await api('/refresh', 'POST'));
    toast('Connections refreshed.');
  });
});

async function start() {
  $('#retry-load').hidden = true;
  try {csrf = (await api('/session')).csrfToken; await reload();}
  catch (error) {$('#loading-message').textContent = error.message; $('#retry-load').hidden = false;}
}
$('#retry-load').addEventListener('click', start);
async function pollState() {
  if (polling || busy || !state || document.hidden || document.querySelector('dialog[open]')) return;
  polling = true;
  try {await reload();} catch {
    if (state.setupComplete) {
      $('#service-notice').textContent = 'Cannot reach the client service. Connection status may be out of date; check that BijouShare is running.';
      $('#service-notice').hidden = false;
    }
  } finally {polling = false;}
}
document.addEventListener('visibilitychange', pollState);
setInterval(pollState, 3000);
start();
