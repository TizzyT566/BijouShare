'use strict';

const $ = selector => document.querySelector(selector);
const tabs = ['overview', 'groups', 'shares', 'devices', 'invites', 'activity', 'settings'];
const entityNames = { shares: 'share', devices: 'device', pendingDevices: 'device request', invites: 'invite' };
const permissionLabels = {
  ListDirectory: 'List folders', ReadData: 'Read files', WriteData: 'Write files',
  CreateFiles: 'Create files', CreateDirectories: 'Create folders', Delete: 'Delete',
  Rename: 'Rename and move', ReadAttributes: 'Read attributes',
  WriteAttributes: 'Write attributes', ReadPermissions: 'Read permissions'
};
let csrf = '', state = null, tab = 'overview', editorSave = null, editorBusy = false;
let pendingDeletion = null, toastTimer;
let viewEpoch = 0, stateLoadSequence = 0;
let devicePollBusy = false;
let connectionHost = location.hostname;
let setupRequired = false;

const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
const nameOf = (list, id) => list.find(item => item.id === id)?.name ?? 'Unknown';
const enabled = value => `<span class="pill ${value ? '' : 'off'}">${value ? 'Enabled' : 'Disabled'}</span>`;
const icon = name => `<span class="bi bi-${name}" aria-hidden="true"></span>`;
const empty = (title, text) => `<div class="empty"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(text)}</p></div>`;
const heading = (title, text, action = '') => `<div class="page-heading"><div><h1 tabindex="-1">${title}</h1><p class="muted">${text}</p></div>${action}</div>`;
const newButton = (label, entity, reason = '') => `<button class="primary" data-new="${entity}" ${reason ? `disabled title="${escapeHtml(reason)}"` : ''}>${icon('plus')} ${label}</button>`;
const serverFolderName = () => `${state.serverName}_${state.serverId.slice(0, 16)}`;

function isLoopbackAddress(host) {
  try {
    const authority = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
    const name = new URL(`http://${authority}`).hostname.toLowerCase().replace(/^\[|\]$/g, '');
    return name === 'localhost' || name.endsWith('.localhost') || name === '::1' || name.startsWith('127.') || name.startsWith('::ffff:7f');
  } catch { return false; }
}

function renderServerIdentity() {
  return `<section class="panel server-identity"><div class="panel-title"><h2>${icon('fingerprint')}Server identity</h2><button type="button" class="quiet small-button" data-copy-fingerprint>${icon('copy')}Copy fingerprint</button></div>
    <div class="panel-body"><dl><div><dt>Verification fingerprint</dt><dd class="mono server-id" id="server-fingerprint">${escapeHtml(state.serverId)}</dd></div><div><dt>Folder on the client drive</dt><dd><code class="server-folder-name">${escapeHtml(serverFolderName())}</code></dd></div></dl></div></section>`;
}

function connectionUri(host, code = '') {
  if (!host || host !== host.trim() || /[\s@/?#\\%]/.test(host) || host.length > 253) throw new Error('Enter the server LAN hostname or IP, without a port or path.');
  const authority = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  let parsed;
  try { parsed = new URL(`http://${authority}:${state.filePort}`); }
  catch { throw new Error('Enter a valid server LAN hostname or IP.'); }
  if (!parsed.hostname || parsed.username || parsed.password || parsed.pathname !== '/') throw new Error('Enter the server hostname or IP only.');
  if (!/^[a-f0-9]{64}$/.test(state.serverId)) throw new Error('The server verification fingerprint is unavailable.');
  return `wad://${parsed.hostname}:${state.filePort}/${state.serverId}${code ? '#' + encodeURIComponent(code) : ''}`;
}

function renderConnectionLink() {
  let uri = '';
  try { uri = connectionUri(connectionHost); } catch { /* Let the address field display a validation error. */ }
  const title = state.inviteOnly ? 'Reconnect an approved device' : 'Connect a client';
  const hint = state.inviteOnly ? 'Approved devices can use this link. For a new device, create an invite in <a href="#invites">Invites</a>.'
    : 'Send the connection link through a trusted channel. New devices will appear in <a href="#devices">Devices</a> for approval.';
  return `<section class="panel connection-panel"><div class="panel-title"><h2>${icon('link')}${title}</h2></div>
    <div class="panel-body"><p class="muted">${hint}</p>
    <label for="connection-host">Server LAN hostname or IP</label><input id="connection-host" value="${escapeHtml(connectionHost)}" maxlength="253" autocomplete="off" spellcheck="false" aria-describedby="connection-host-hint${isLoopbackAddress(connectionHost) ? ' connection-local-warning' : ''}">
    <p id="connection-host-hint" class="hint">Use an address the client can reach on port ${state.filePort}.</p><p id="connection-local-warning" class="address-warning" role="status" ${isLoopbackAddress(connectionHost) ? '' : 'hidden'}>This address points to the client itself. Enter the server’s LAN address to connect another device.</p>
    <output id="connection-uri" class="mono">${escapeHtml(uri)}</output><div class="connection-actions"><button type="button" data-copy-connection>${icon('copy')}Copy link</button><a id="connection-link" class="button-link quiet" ${uri ? `href="${escapeHtml(uri)}"` : ''}>Open BijouShare${icon('arrow')}</a></div><p id="connection-error" class="error" role="alert"></p></div></section>`;
}

function shareActions(share) {
  const name = escapeHtml(share.name);
  return `<div class="actions"><button class="quiet" data-edit="shares" data-id="${share.id}" aria-label="Edit share ${name}">Edit</button><button class="quiet danger" data-delete="shares" data-id="${share.id}" aria-label="Remove share ${name}">Remove</button></div>`;
}

function table(headers, rows, title = '', message = 'Add an item to get started.') {
  const label = title || `${tab[0].toUpperCase() + tab.slice(1)} list`;
  return `<div class="panel">${title ? `<div class="panel-title"><h2>${escapeHtml(title)}</h2><span>${rows.length} total</span></div>` : ''}${rows.length
    ? `<div class="table-wrap" tabindex="0" role="region" aria-label="${escapeHtml(label)}"><table><thead><tr>${headers.map(header => `<th scope="col">${header || '<span class="sr-only">Actions</span>'}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`
    : empty('Nothing here yet', message)}</div>`;
}

async function api(path, method = 'GET', body) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  try {
    const response = await fetch('/api' + path, {
      method, credentials: 'same-origin', signal: controller.signal,
      headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': csrf },
      body: body === undefined ? undefined : JSON.stringify(body)
    });
    if (response.status === 401) {
      const message = path === '/login' ? 'Administrator name or password is incorrect.' : 'Your session ended. Sign in to continue.';
      showLogin();
      $('#login-error').textContent = message;
      throw new Error(message);
    }
    const text = await response.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { /* Handle non-JSON error pages below. */ }
    if (!response.ok) {
      const fallback = response.status === 429 ? 'Too many sign-in attempts. Try again in a minute.'
        : response.status >= 500 ? 'The server could not complete this request. Check its logs and refresh.'
          : `Request failed (${response.status}).`;
      throw new Error(data?.error ?? fallback);
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('The server did not respond in time. Refresh its state before retrying a change.', { cause: error });
    if (error instanceof TypeError) throw new Error('Cannot reach the server. Check the connection and refresh its state before retrying a change.', { cause: error });
    throw error;
  } finally { clearTimeout(timeout); }
}

async function session() {
  const result = await api('/session');
  for (const label of document.querySelectorAll('[data-version]'))
    label.textContent = result.version ? ' · v' + result.version : '';
  csrf = result.csrfToken;
  $('#crypto-warning').hidden = result.cryptoSupported !== false;
  $('#retry-session').hidden = true;
  setupRequired = result.setupRequired === true;
  $('#admin-name').textContent = result.name ?? '';
  return result;
}

function showLogin() {
  viewEpoch++;
  stateLoadSequence++;
  state = null;
  resetGroupWorkspace();
  resetDeviceWorkspace();
  $('#content').replaceChildren();
  $('#admin-name').textContent = '';
  $('#server-name').textContent = 'Server';
  $('#server-name').removeAttribute('title');
  $('#app').hidden = true;
  $('#server-loading').hidden = true;
  $('#login-screen').hidden = false;
  $('#setup-screen').hidden = true;
  clearSetupSecrets();
  $('#login').elements.password.value = '';
  resetPasswordVisibility('#login');
  $('#editor').close();
  $('#confirmation').close();
  closeInviteDetails();
  pendingDeletion = null;
  document.title = 'BijouShare · Sign in';
}

function clearSetupSecrets() {
  $('#setup-password').value = '';
  $('#setup-confirmation').value = '';
  $('#setup-confirmation').setCustomValidity('');
  resetPasswordVisibility('#setup');
}

function resetPasswordVisibility(container) {
  document.querySelectorAll(`${container} [data-password-toggle]`).forEach(button => {
    const input = document.getElementById(button.dataset.passwordToggle);
    input.type = 'password'; button.setAttribute('aria-pressed', 'false'); button.textContent = 'Show';
    button.setAttribute('aria-label', input.id === 'setup-confirmation' ? 'Show password confirmation' : 'Show password');
  });
}
document.querySelectorAll('[data-password-toggle]').forEach(button => button.addEventListener('click', () => {
  const input = document.getElementById(button.dataset.passwordToggle), visible = input.type === 'password';
  input.type = visible ? 'text' : 'password';
  button.setAttribute('aria-pressed', String(visible)); button.textContent = visible ? 'Hide' : 'Show';
  button.setAttribute('aria-label', `${visible ? 'Hide' : 'Show'} ${input.id === 'setup-confirmation' ? 'password confirmation' : 'password'}`);
}));

function showSetup() {
  showLogin();
  $('#login-screen').hidden = true;
  $('#setup-screen').hidden = false;
  $('#setup-error').textContent = '';
  document.title = 'BijouShare · Set up server';
  $('#setup-server-name').focus();
}

function validateSetupFields() {
  const admin = $('#setup-admin-name'), password = $('#setup-password'), confirmation = $('#setup-confirmation');
  admin.setCustomValidity(admin.value !== admin.value.trim() || /[\u0000-\u001f\u007f-\u009f]/.test(admin.value)
    ? 'Use an administrator name without surrounding whitespace or control characters.' : '');
  confirmation.setCustomValidity(confirmation.value && confirmation.value !== password.value ? 'The passwords do not match.' : '');
}
$('#setup').addEventListener('input', validateSetupFields);
$('#setup').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget;
  validateSetupFields();
  if (!form.reportValidity()) return;
  const values = new FormData(form);
  setBusy(form, true); $('#setup-error').textContent = '';
  try {
    const current = await session();
    if (!current.setupRequired) {
      showLogin(); $('#login-error').textContent = 'This server is already configured. Sign in to continue.'; return;
    }
    await api('/setup', 'POST', {
      serverName: values.get('serverName'), adminName: values.get('adminName'),
      password: values.get('password'), confirmPassword: values.get('confirmPassword')
    });
    const administrator = values.get('adminName');
    form.reset(); clearSetupSecrets(); setupRequired = false;
    showLogin(); $('#login').elements.name.value = administrator;
    await session();
    $('#login-error').textContent = '';
    toast('Server created. Sign in with your administrator account.');
    $('#login').elements.password.focus();
  } catch (error) {
    clearSetupSecrets();
    if ($('#setup-screen').hidden) $('#login-error').textContent = error.message;
    else { $('#setup-error').textContent = error.message; $('#setup-password').focus(); }
  } finally { setBusy(form, false); }
});

async function reload() {
  const epoch = viewEpoch, sequence = ++stateLoadSequence;
  const updated = await api('/state');
  if (epoch !== viewEpoch || sequence !== stateLoadSequence) return false;
  state = updated;
  render();
  return true;
}
async function enter() {
  if (await reload()) { $('#server-loading').hidden = true; $('#login-screen').hidden = true; $('#setup-screen').hidden = true; $('#app').hidden = false; }
}

function canRefreshDevices() {
  return state && (tab === 'devices' || tab === 'invites') && !document.hidden && !editorBusy && !$('#refresh').disabled &&
    (tab !== 'devices' || !deviceWorkspaceEditing()) &&
    !$('#editor').open && !$('#confirmation').open && !$('#invite-result').open && !document.activeElement?.closest('#content');
}
setInterval(async () => {
  if (devicePollBusy || !canRefreshDevices()) return;
  devicePollBusy = true;
  const epoch = viewEpoch, sequence = ++stateLoadSequence;
  try {
    const updated = await api('/state');
    if (epoch !== viewEpoch || sequence !== stateLoadSequence || !canRefreshDevices()) return;
    const changed = state.inviteOnly !== updated.inviteOnly ||
      JSON.stringify([state.devices, state.pendingDevices, state.invites, state.groups, state.serverName, state.serverId]) !==
      JSON.stringify([updated.devices, updated.pendingDevices, updated.invites, updated.groups, updated.serverName, updated.serverId]);
    state = updated;
    if (changed) render();
  } catch { /* Keep the visible state and manual Refresh available after transient network failures. */ }
  finally { devicePollBusy = false; }
}, 5000);

function toast(message) {
  clearTimeout(toastTimer);
  $('#toast').textContent = message;
  $('#toast').hidden = false;
  toastTimer = setTimeout(() => { $('#toast').hidden = true; }, 6500);
}

function setBusy(form, busy) {
  form.setAttribute('aria-busy', String(busy));
  form.querySelectorAll('button').forEach(button => { button.disabled = busy; });
  if (form.id === 'editor-form') $('#editor-fields').inert = busy;
}

$('#login').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget, fields = new FormData(form);
  setBusy(form, true); $('#login-error').textContent = '';
  try {
    const current = await session();
    if (current.setupRequired) { showSetup(); return; }
    await api('/login', 'POST', { name: fields.get('name').trim(), password: fields.get('password') });
    form.elements.password.value = '';
    await session(); await enter();
  } catch (error) { $('#login-error').textContent = error.message; form.elements.password.focus(); }
  finally { setBusy(form, false); }
});

$('#logout').addEventListener('click', async () => {
  $('#logout').disabled = true;
  try { await api('/logout', 'POST'); showLogin(); await session(); }
  catch (error) { toast(error.message); }
  finally { $('#logout').disabled = false; }
});
$('#refresh').addEventListener('click', async () => {
  $('#refresh').disabled = true;
  try { await reload(); toast('Server state refreshed.'); }
  catch (error) { toast(error.message); }
  finally { $('#refresh').disabled = false; }
});
$('#skip-navigation').addEventListener('click', event => { event.preventDefault(); $('#content').focus(); });
const navToggle = $('#nav-toggle');
function closeMobileNavigation() {
  navToggle.setAttribute('aria-expanded', 'false');
}
navToggle.addEventListener('click', () => navToggle.setAttribute('aria-expanded', String(navToggle.getAttribute('aria-expanded') === 'false')));
window.addEventListener('hashchange', () => {
  if (!state) return;
  closeMobileNavigation();
  render();
  $('#content h1')?.focus({preventScroll: true});
  window.scrollTo(0, 0);
});
$('#rail-body nav').addEventListener('click', event => {
  if (event.target.closest('a')?.getAttribute('aria-current') === 'page' && navToggle.getAttribute('aria-expanded') === 'true') {
    closeMobileNavigation();
    $('#content h1')?.focus();
  }
});

function permissionText(mask) {
  const all = state.permissions.reduce((value, permission) => value | permission.value, 0);
  if (mask === all) return 'Full control';
  if (!mask) return 'None';
  return state.permissions.filter(permission => (mask & permission.value) !== 0)
    .map(permission => permissionLabels[permission.name] ?? permission.name).join(', ');
}

function renderOverview() {
  const { groups, shares, devices, pendingDevices, activity } = state;
  const pending = pendingDevices.filter(device => !device.rejected).length;
  const metrics = [
    ['shares', 'folder', 'Shared locations', shares.length],
    ['devices', 'devices', 'Approved devices', devices.length],
    ['groups', 'users', 'Access groups', groups.length],
    state.inviteOnly ? ['invites', 'key', 'Active invites', state.invites.filter(invite => inviteStatus(invite) === 'Active').length]
      : ['devices', 'clock', 'Awaiting approval', pending]
  ];
  const listing = shares.slice(0, 4).map(share => `<li>
    <span class="row-icon">${icon('folder')}</span><div class="row-copy"><strong>${escapeHtml(share.name)}</strong><small class="mono">${escapeHtml(share.localPath)}</small></div>${enabled(share.enabled)}</li>`).join('');
  const events = activity.slice(0, 3).map(event => {
    const action = event.action.replace(/([a-z])([A-Z])/g, '$1 $2');
    return `<li><span class="row-icon">${icon(event.result === 'OK' ? 'activity' : 'alert')}</span><div class="row-copy"><strong>${escapeHtml(action)}</strong><small>${escapeHtml(event.actor)}${event.result === 'OK' ? '' : ' · ' + escapeHtml(event.result)}</small></div><time datetime="${escapeHtml(event.time)}" title="${escapeHtml(new Date(event.time).toLocaleString())}">${escapeHtml(new Date(event.time).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'}))}</time></li>`;
  }).join('');
  return `<section class="server-hero" aria-labelledby="overview-title"><div class="hero-copy"><p class="eyebrow">${icon('server')}Server overview</p><h1 id="overview-title" tabindex="-1">${escapeHtml(state.serverName)}</h1><div class="hero-meta"><span>${icon('network')}TCP <code>${state.filePort}</code></span><span class="hero-divider"></span><span>${icon('lock')}Encrypted file server</span></div>
      <div class="hero-actions">${newButton('Add share', 'shares')}<button type="button" data-new="invites">${icon('key')}Create invite</button></div></div></section>
    <div class="stats" aria-label="Server totals">${metrics.map(([target, symbol, label, value]) => `<a class="stat" href="#${target}"><span class="stat-label">${label}</span><strong>${value.toLocaleString()}</strong><span class="stat-symbol">${icon(symbol)}</span></a>`).join('')}</div>
    ${pending && !state.inviteOnly ? `<div class="callout approval-notice">${icon('clock')}<div><strong>${pending} device ${pending === 1 ? 'request awaits' : 'requests await'} approval</strong><span>Review the identities and assign their access groups.</span></div><a class="text-link" href="#devices">Review requests${icon('arrow')}</a></div>` : ''}
    <div class="overview-grid">
      <section class="panel summary-panel"><div class="panel-title"><h2>${icon('folder')}Shared locations</h2><a class="text-link" href="#shares">View shares${icon('arrow')}</a></div>${listing ? `<ul class="summary-list">${listing}</ul>` : empty('No shared locations', 'Add a file, folder, or drive to start sharing.')}</section>
      <section class="panel summary-panel"><div class="panel-title"><h2>${icon('activity')}Recent activity</h2><a class="text-link" href="#activity">View log${icon('arrow')}</a></div>${events ? `<ul class="summary-list">${events}</ul>` : empty('No recent events', 'Connections and file operations will appear here.')}</section>
      ${renderConnectionLink()}${renderServerIdentity()}
    </div>`;
}

function renderSharesTable(title = '') {
  return table(['Name on virtual drive', 'Server path', 'Status', ''], state.shares.map(share =>
    `<tr><td><strong>${escapeHtml(share.name)}</strong></td><td class="mono">${escapeHtml(share.localPath)}</td><td>${enabled(share.enabled)}</td><td>${shareActions(share)}</td></tr>`), title, 'Add a file, folder, or drive to begin sharing.');
}

const formattedFingerprint = value => String(value ?? '').match(/.{1,8}/g)?.join(' ') ?? '';
const deviceGroups = device => device.groupIds.map(id => `<span class="pill">${escapeHtml(nameOf(state.groups, id))}</span>`).join(' ') || '<span class="muted">No groups — no access</span>';
const timeText = value => `<time datetime="${escapeHtml(value)}">${escapeHtml(new Date(value).toLocaleString())}</time>`;

function inviteStatus(invite) {
  if (invite.revoked) return 'Revoked';
  if (invite.expiresUtc && new Date(invite.expiresUtc).getTime() <= Date.now()) return 'Expired';
  if (invite.maxUses !== null && invite.uses >= invite.maxUses) return 'Used up';
  return 'Active';
}

function renderInvites() {
  const hint = state.inviteOnly ? 'Invite-only enrollment is on. Every new device needs a valid invite link.'
    : 'Automatically approve new devices into the groups you choose.';
  return heading('Invites', hint, newButton('Create invite', 'invites')) +
    `<div class="callout"><strong>Each invite grants its selected group memberships.</strong>Set a use limit and an expiration, or allow unlimited uses and no expiration. Existing devices keep their current groups; blocked devices remain blocked. Copy each new code when it is created.</div>` +
    table(['Invite', 'Groups', 'Uses', 'Expires', 'Status', ''], (state.invites ?? []).map(invite => {
      const status = inviteStatus(invite);
      const action = invite.revoked ? 'Remove' : 'Revoke';
      return `<tr data-invite-id="${escapeHtml(invite.id)}"><td><strong>${escapeHtml(invite.name)}</strong><small>Created ${timeText(invite.createdUtc)}</small></td><td>${deviceGroups(invite)}</td><td>${invite.maxUses === null ? `${invite.uses} used · unlimited` : `${invite.uses} of ${invite.maxUses} used`}<small>${invite.maxUses === null ? 'No use limit' : Math.max(0, invite.maxUses - invite.uses) + ' remaining'}</small></td><td>${invite.expiresUtc ? timeText(invite.expiresUtc) : 'Never'}</td><td><span class="pill ${status === 'Active' ? '' : 'off'}">${status}</span></td><td><button type="button" class="quiet danger" ${invite.revoked ? 'data-remove-record' : 'data-delete'}="invites" data-id="${escapeHtml(invite.id)}" aria-label="${action} invite ${escapeHtml(invite.name)}">${action}</button></td></tr>`;
    }), 'Enrollment invites', 'Create an invite and share its link with the devices you want to enroll.');
}

function renderActivity() {
  return heading('Activity', 'Recent connections, file changes, and administrative actions.') +
    table(['Time', 'Actor', 'Action', 'Target', 'Result'], state.activity.map(event =>
      `<tr><td><time datetime="${escapeHtml(event.time)}">${escapeHtml(new Date(event.time).toLocaleString())}</time></td><td>${escapeHtml(event.actor)}</td><td>${escapeHtml(event.action)}</td><td class="mono">${escapeHtml(event.target)}</td><td><span class="pill ${event.result === 'OK' ? '' : 'denied'}">${escapeHtml(event.result)}</span>${event.detail ? `<small>${escapeHtml(event.detail)}</small>` : ''}</td></tr>`), 'Recent events', 'Events appear here as the server is used.') +
    '<p class="hint">The latest 200 retained audit events are shown. Complete daily audit files are stored on the server.</p>';
}

function renderSettings() {
  const browserPort = Number(location.port || (location.protocol === 'https:' ? 443 : 80));
  const canChangeWebPort = browserPort === state.webPort && state.webPortEditable !== false;
  let webPortHint = 'This page will reopen on the new port when the web UI is ready.';
  if (state.webPort == null) webPortHint = 'The web listener is managed by the server’s hosting configuration.';
  else if (!canChangeWebPort) webPortHint = 'To change this port, open the console directly from the BijouShare Server tray icon.';
  else if (!isLoopbackAddress(location.hostname)) webPortHint = 'Allow the new port through your firewall before saving. This page will reopen on that port.';
  return heading('Settings', 'Manage device enrollment, server identity, listening ports, and administrator access.') +
    `<div class="settings-grid">${renderServerIdentity()}${renderConnectionLink()}` +
    `<section class="panel"><div class="panel-title"><h2>${icon('devices')}Device enrollment</h2></div>
      <form id="device-enrollment" class="password-form">
        <label class="check"><input type="checkbox" id="invite-only" name="inviteOnly" aria-describedby="enrollment-hint" ${state.inviteOnly ? 'checked' : ''}>Invite only</label>
        <p id="enrollment-hint" class="hint">Require a valid invite link for each new device. This pauses manual approvals. Approved devices can reconnect as usual.</p>
        <p id="enrollment-error" class="error" role="alert"></p><button class="primary" type="submit">Save enrollment settings</button>
      </form></section>` +
    `<div class="panel"><div class="panel-title"><h2>${icon('server')}Server name</h2></div><form id="rename-server" class="password-form">
      <label>Display name<input name="name" required maxlength="100" pattern="[A-Za-z0-9\\-]+" spellcheck="false" value="${escapeHtml(state.serverName)}" aria-describedby="rename-hint"></label>
      <p id="rename-hint" class="hint">Clients see the new folder name when they reconnect. Existing links and fingerprints stay valid.</p>
      <p id="rename-error" class="error" role="alert"></p><button class="primary" type="submit">Save name</button></form></div>` +
    `<section class="panel"><div class="panel-title"><h2>${icon('link')}Listening ports</h2></div>
      <form id="server-ports" class="password-form">
        <label for="file-port">File service port</label><input id="file-port" name="filePort" type="number" min="1" max="65535" required value="${escapeHtml(state.filePort)}" aria-describedby="file-port-hint">
        <p id="file-port-hint" class="hint">Allow this TCP port through your firewall. Clients will need the new port to reconnect.</p>
        <label for="web-port">Web UI port</label><input id="web-port" name="webPort" type="number" min="1" max="65535" ${canChangeWebPort ? 'required' : 'disabled'} value="${escapeHtml(state.webPort)}" aria-describedby="web-port-hint">
        <p id="web-port-hint" class="hint">${webPortHint}</p>
        <p id="ports-error" class="error" role="alert"></p><button class="primary" type="submit">Save ports</button>
      </form></section>` +
    `<div class="panel"><div class="panel-title"><h2>${icon('key')}Administrator password</h2></div><form id="password-form" class="password-form">
      <label>Current password<input name="currentPassword" type="password" autocomplete="current-password" required maxlength="1024"></label>
      <label>New password<input name="newPassword" type="password" autocomplete="new-password" minlength="14" maxlength="1024" required aria-describedby="password-hint"></label>
      <label>Confirm new password<input name="confirmation" type="password" autocomplete="new-password" minlength="14" maxlength="1024" required></label>
      <span class="hint" id="password-hint">At least 14 characters. Changing it ends existing administrator sessions.</span><p id="password-error" class="error" role="alert"></p><button type="submit" class="primary">Update password</button></form></div></div>`;
}

function render() {
  if (location.hash === '#permissions') history.replaceState(history.state, '', '#groups');
  const requested = location.hash.slice(1) || 'overview';
  tab = tabs.includes(requested) ? requested : 'overview';
  const label = tab[0].toUpperCase() + tab.slice(1);
  document.querySelectorAll('[data-tab]').forEach(link => {
    link.classList.toggle('active', link.dataset.tab === tab);
    if (link.dataset.tab === tab) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
  });
  const pendingCount = state.pendingDevices.filter(device => !device.rejected).length;
  const deviceLink = document.querySelector('[data-tab="devices"]');
  let badge = deviceLink.querySelector('.nav-badge');
  if (pendingCount && !state.inviteOnly) {
    if (!badge) { badge = document.createElement('span'); badge.className = 'nav-badge'; deviceLink.append(badge); }
    badge.textContent = pendingCount; badge.setAttribute('aria-label', `${pendingCount} pending device ${pendingCount === 1 ? 'request' : 'requests'}`);
  } else if (badge) badge.remove();
  $('#server-name').textContent = state.serverName;
  $('#server-name').title = serverFolderName();
  $('#crumb').textContent = label; document.title = `${state.serverName} · ${label} · BijouShare`;
  const renderers = {
    overview: renderOverview, groups: renderGroupWorkspace,
    shares: () => heading('Shares', 'Files, folders, and entire drives, together under one virtual drive.', newButton('Add share', 'shares')) + renderSharesTable() +
      (state.storageAccount ? `<p class="hint">Windows accesses these paths as <strong>${escapeHtml(state.storageAccount)}</strong>. This account needs NTFS write access on each folder where devices can create files or folders.</p>` : ''),
    devices: renderDeviceWorkspace, invites: renderInvites, activity: renderActivity, settings: renderSettings
  };
  $('#content').innerHTML = renderers[tab]();
  $('#device-enrollment')?.addEventListener('submit', changeEnrollment);
  $('#rename-server')?.addEventListener('submit', changeServerName);
  $('#server-ports')?.addEventListener('submit', changeServerPorts);
  $('#password-form')?.addEventListener('submit', changePassword);
}

function field(name, label, value = '', hint = '') {
  const id = `editor-${name}`;
  return `<label for="${id}">${label}</label><input id="${id}" name="${name}" value="${escapeHtml(value)}" required maxlength="${name === 'localPath' || name === 'path' ? '2048' : '100'}" ${hint ? `aria-describedby="${id}-hint"` : ''}>${hint ? `<span class="hint" id="${id}-hint">${hint}</span>` : ''}`;
}

function inviteGroupFields() {
  const groups = state.groups.filter(group => !group.isAdministrator);
  return `<fieldset class="memberships"><legend>Group memberships</legend><div class="check-grid">${groups.map(group => `<label class="check"><input type="checkbox" name="group" value="${group.id}">${escapeHtml(group.name)}</label>`).join('') || '<p class="hint">Create a custom group to include permissions in an invite.</p>'}</div></fieldset><p class="hint">Administrator can only be assigned directly to a device. An invite with no groups grants no file access.</p>`;
}

function openEditor(title, fields, save, buttonLabel = 'Save changes') {
  $('#editor-title').textContent = title; $('#editor-fields').innerHTML = fields;
  $('#editor-error').textContent = ''; $('#editor-submit').textContent = buttonLabel;
  editorSave = save; $('#editor').showModal();
}

function localDateTime(value) {
  const date = new Date(value);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

function createInvite() {
  openEditor('Create invite', field('name', 'Invite name', '', 'A label for keeping track of this invitation.') + inviteGroupFields() +
    `<div class="invite-limits"><fieldset><legend>Number of uses</legend><label class="check"><input type="checkbox" name="unlimitedUses">Unlimited uses</label><label for="invite-max-uses">Use limit</label><input id="invite-max-uses" name="maxUses" type="number" min="1" max="1000000" step="1" value="1" required><p class="hint">Each newly enrolled device uses one. Reconnecting an enrolled device uses none.</p></fieldset><fieldset><legend>Expiration</legend><label class="check"><input type="checkbox" name="neverExpires">Never expires</label><label for="invite-expires">Expires at</label><input id="invite-expires" name="expiresUtc" type="datetime-local" value="${localDateTime(Date.now() + 7 * 24 * 60 * 60 * 1000)}" required><p class="hint">Shown in your local time zone. The server checks expiration on enrollment.</p></fieldset></div>`,
    async form => {
      const values = new FormData(form);
      const maxUses = values.has('unlimitedUses') ? null : Number(values.get('maxUses'));
      if (maxUses !== null && (!Number.isSafeInteger(maxUses) || maxUses < 1 || maxUses > 1000000)) throw new Error('Choose a whole-number use limit from 1 to 1,000,000.');
      const expires = values.has('neverExpires') ? null : new Date(values.get('expiresUtc'));
      if (expires !== null && (!Number.isFinite(expires.getTime()) || expires.getTime() <= Date.now())) throw new Error('Choose an expiration in the future, or select Never expires.');
      const invite = await api('/invites', 'POST', { name: values.get('name').trim(), groupIds: values.getAll('group'), maxUses, expiresUtc: expires?.toISOString() ?? null });
      return { message: 'Invite created. Copy its code before closing the details.', invite };
    }, 'Create invite');
}

function updateConnectionLink() {
  const host = $('#connection-host');
  if (!host) return;
  connectionHost = host.value;
  const localOnly = isLoopbackAddress(connectionHost);
  $('#connection-local-warning').hidden = !localOnly;
  host.setAttribute('aria-describedby', 'connection-host-hint' + (localOnly ? ' connection-local-warning' : ''));
  try {
    const uri = connectionUri(connectionHost);
    $('#connection-uri').textContent = uri; $('#connection-link').href = uri;
    $('#connection-link').removeAttribute('aria-disabled'); $('#connection-error').textContent = '';
    $('[data-copy-connection]').disabled = false;
  } catch (error) {
    $('#connection-uri').textContent = ''; $('#connection-link').removeAttribute('href');
    $('#connection-link').setAttribute('aria-disabled', 'true'); $('#connection-error').textContent = error.message;
    $('[data-copy-connection]').disabled = true;
  }
}

function updateInviteLink() {
  if (!state || !$('#invite-result').open) return;
  const localOnly = isLoopbackAddress($('#invite-link-host').value);
  $('#invite-local-warning').hidden = !localOnly;
  $('#invite-link-host').setAttribute('aria-describedby', 'invite-host-hint' + (localOnly ? ' invite-local-warning' : ''));
  try {
    const uri = connectionUri($('#invite-link-host').value, $('#invite-code').value);
    $('#invite-uri').value = uri; $('#open-invite-link').href = uri;
    $('#open-invite-link').removeAttribute('aria-disabled'); $('#invite-link-error').textContent = '';
    $('[data-copy-invite-link]').disabled = false;
  } catch (error) {
    $('#invite-uri').value = ''; $('#open-invite-link').removeAttribute('href');
    $('#open-invite-link').setAttribute('aria-disabled', 'true'); $('#invite-link-error').textContent = error.message;
    $('[data-copy-invite-link]').disabled = true;
  }
}

function showCreatedInvite(invite) {
  $('#invite-code').value = invite.code;
  $('#invite-link-host').value = connectionHost;
  $('#invite-result').showModal(); updateInviteLink(); $('#invite-code').focus(); $('#invite-code').select();
}

async function copyField(selector, label) {
  const field = $(selector), value = field.value ?? field.textContent;
  try {
    if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
    await navigator.clipboard.writeText(value);
    toast(`${label} copied.`);
  } catch {
    if (field.select) { field.focus(); field.select(); }
    else { const range = document.createRange(); range.selectNodeContents(field); const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range); }
    try { if (document.execCommand('copy')) { toast(`${label} copied.`); return; } } catch { /* Keep the text selected for manual copying. */ }
    toast(`Copy the selected ${label.toLowerCase()} with Ctrl+C.`);
  }
}

document.addEventListener('input', event => {
  if (event.target.id === 'connection-host') updateConnectionLink();
  if (event.target.id === 'invite-link-host') updateInviteLink();
});
$('#editor-form').addEventListener('change', event => {
  if (event.target.name === 'unlimitedUses') {
    $('#invite-max-uses').disabled = event.target.checked; $('#invite-max-uses').required = !event.target.checked;
  }
  if (event.target.name === 'neverExpires') {
    $('#invite-expires').disabled = event.target.checked; $('#invite-expires').required = !event.target.checked;
  }
});
function clearInviteDetails() {
  $('#invite-code').value = ''; $('#invite-uri').value = ''; $('#invite-link-host').value = '';
  $('#open-invite-link').removeAttribute('href'); $('#invite-link-error').textContent = '';
}
function closeInviteDetails() {
  clearInviteDetails();
  $('#invite-result').close();
}
$('#close-invite-result').addEventListener('click', closeInviteDetails);
$('#done-invite-result').addEventListener('click', closeInviteDetails);
$('#invite-result').addEventListener('cancel', clearInviteDetails);
$('#invite-result').addEventListener('close', clearInviteDetails);

function editShare(id) {
  const existing = state.shares.find(share => share.id === id);
  const share = existing ?? { id: crypto.randomUUID(), enabled: true };
  const fields = field('name', 'Name on virtual drive', share.name) +
    field('localPath', 'Absolute server path', share.localPath, 'Examples: D:\\, D:\\Team, or D:\\Reports\\summary.pdf') +
    `<label class="check"><input type="checkbox" name="enabled" ${share.enabled ? 'checked' : ''}>Enabled</label>`;
  openEditor(`${existing ? 'Edit' : 'Add'} share`, fields, async form => {
    const values = new FormData(form);
    const name = values.get('name').trim();
    if (!name) throw new Error('Enter a name with at least one non-space character.');
    await api(`/shares/${share.id}`, 'PUT', { id: share.id, name, localPath: values.get('localPath').trim(), enabled: values.has('enabled') });
    return 'Changes saved.';
  });
}

function confirmDeletion(entity, id, removeRecord = false) {
  const item = state[entity].find(value => value.id === id);
  if (!item) return;
  const name = item.name;
  let title = `Delete ${entityNames[entity]}?`, detail = '', button = 'Delete';
  if (entity === 'shares') { title = 'Remove share?'; button = 'Remove share'; detail = `Clients will lose this shared location and ${state.rules.filter(rule => rule.shareId === id).length} permission rule(s) will be removed. The server’s files remain in place.`; }
  if (entity === 'devices') { title = 'Block device?'; button = 'Block device'; detail = 'This device loses access immediately. Its identity and groups are retained. Expand its name and select Enabled to allow it to reconnect.'; }
  if (entity === 'pendingDevices') { title = 'Block device?'; button = 'Block device'; detail = 'Blocked devices cannot enroll, even with a valid invite link.'; }
  if (entity === 'invites') { title = 'Revoke invite?'; button = 'Revoke invite'; detail = 'This code will no longer enroll devices. Devices already enrolled keep their current groups and permissions.'; }
  if (removeRecord) {
    if (entity === 'invites' && item.revoked) {
      title = 'Remove revoked invite?'; button = 'Remove invite';
      detail = 'Permanently remove this invite from the list. Its code stays revoked.';
    } else if ((entity === 'devices' && !item.enabled) || (entity === 'pendingDevices' && item.rejected)) {
      title = 'Forget blocked device?'; button = 'Forget device';
      const effect = entity === 'devices' ? 'This permanently removes the device and its group memberships and clears its block.'
        : 'This permanently removes the rejected request and clears the device’s block.';
      const enrollment = state.inviteOnly ? 'Invite-only enrollment is on, so the device needs a valid invite to enroll again.'
        : 'The device can request approval again or enroll with a valid invite.';
      detail = effect + ' ' + enrollment;
    } else return;
  }
  $('#confirmation-title').textContent = title; $('#confirmation-name').textContent = name;
  $('#confirmation-id').hidden = !removeRecord;
  $('#confirmation-id').textContent = removeRecord ? 'Record ID ' + id : '';
  $('#confirmation-detail').textContent = detail; $('#confirm-delete').textContent = button;
  $('#confirmation-error').textContent = ''; pendingDeletion = { entity, id, removeRecord };
  $('#confirmation').showModal(); $('#cancel-deletion').focus();
}
$('#confirm-delete').addEventListener('click', async () => {
  if (!pendingDeletion) return;
  const { entity, id, removeRecord } = pendingDeletion;
  const epoch = viewEpoch;
  const message = removeRecord ? (entity === 'invites' ? 'Revoked invite removed.' : 'Device forgotten. Its block has been cleared.')
    : entity === 'devices' || entity === 'pendingDevices' ? 'Device blocked.' : entity === 'shares' ? 'Share removed.' : entity === 'invites' ? 'Invite revoked.' : 'Item deleted.';
  let deleted = false;
  setBusy($('#confirmation-form'), true);
  try {
    const endpoint = entity === 'pendingDevices' ? 'pending-devices' : entity;
    await api(`/${endpoint}/${encodeURIComponent(id)}${removeRecord ? '/record' : ''}`, 'DELETE');
    deleted = true;
    if (!state || epoch !== viewEpoch) return;
    $('#confirmation').close(); pendingDeletion = null;
    if (removeRecord) {
      ++stateLoadSequence;
      state[entity] = state[entity].filter(item => item.id !== id);
      render();
    }
    await reload(); toast(message);
  } catch (error) {
    if (deleted) toast(`${message} The list could not be refreshed. ${error.message}`);
    else if ($('#confirmation').open) $('#confirmation-error').textContent = error.message;
    else toast(error.message);
  }
  finally { setBusy($('#confirmation-form'), false); }
});
$('#cancel-deletion').addEventListener('click', () => $('#confirmation').close());
$('#confirmation').addEventListener('cancel', event => { if ($('#confirmation-form').getAttribute('aria-busy') === 'true') event.preventDefault(); });
$('#confirmation').addEventListener('close', () => { pendingDeletion = null; });

document.addEventListener('click', event => {
  const button = event.target.closest('button');
  if (!button || button.disabled || !state) return;
  if (button.dataset.new === 'invites') createInvite();
  else if (button.dataset.new === 'shares' || button.dataset.edit === 'shares') editShare(button.dataset.id);
  else if (button.dataset.removeRecord) confirmDeletion(button.dataset.removeRecord, button.dataset.id, true);
  else if (button.dataset.delete) confirmDeletion(button.dataset.delete, button.dataset.id);
  else if (button.hasAttribute('data-copy-connection')) copyField('#connection-uri', 'Server link');
  else if (button.hasAttribute('data-copy-fingerprint')) copyField('#server-fingerprint', 'Server fingerprint');
  else if (button.hasAttribute('data-copy-invite-code')) copyField('#invite-code', 'Invite code');
  else if (button.hasAttribute('data-copy-invite-link')) copyField('#invite-uri', 'Invite link');
});
$('#editor-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (editorBusy) return;
  const form = event.currentTarget;
  let savedMessage = null, savedResult = null;
  editorBusy = true; setBusy(form, true); $('#editor-error').textContent = '';
  try { savedResult = await editorSave(form); savedMessage = typeof savedResult === 'string' ? savedResult : savedResult.message; $('#editor').close(); await reload(); toast(savedMessage); }
  catch (error) {
    if (savedMessage) toast(`${savedMessage} The list could not be refreshed. ${error.message}`);
    else if ($('#editor').open) $('#editor-error').textContent = error.message;
    else toast(error.message);
  }
  finally { editorBusy = false; setBusy(form, false); if (savedResult?.invite && state) showCreatedInvite(savedResult.invite); }
});
function closeEditor() { if (!editorBusy) $('#editor').close(); }
$('#editor').addEventListener('cancel', event => { if (editorBusy) event.preventDefault(); });
$('#close-editor').addEventListener('click', closeEditor);
$('#cancel-editor').addEventListener('click', closeEditor);
$('#editor').addEventListener('cancel', event => { if (editorBusy) event.preventDefault(); });

async function changeServerName(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const name = form.elements.name.value;
  const error = $('#rename-error');
  error.textContent = '';
  setBusy(form, true);
  try {
    await api('/server/name', 'POST', {name});
    await reload();
    toast('Server name updated.');
  } catch (exception) { error.textContent = exception.message; }
  finally { setBusy(form, false); }
}

async function changeEnrollment(event) {
  event.preventDefault();
  const form = event.currentTarget, input = form.elements.inviteOnly;
  if (input.disabled) return;
  const epoch = viewEpoch, error = $('#enrollment-error');
  error.textContent = '';
  input.disabled = true;
  setBusy(form, true);
  try {
    const saved = await api('/server/enrollment', 'POST', { inviteOnly: input.checked });
    if (!state || viewEpoch !== epoch) return;
    ++stateLoadSequence;
    state.inviteOnly = saved.inviteOnly;
    render();
    if (tab === 'settings') $('#invite-only').focus({ preventScroll: true });
    toast(saved.inviteOnly ? 'Invite-only enrollment enabled.' : 'Manual enrollment requests enabled.');
  } catch (exception) {
    if (error.isConnected) error.textContent = exception.message;
    else if (viewEpoch === epoch) toast(exception.message);
  } finally {
    input.disabled = false;
    setBusy(form, false);
  }
}

$('#web-restarting').addEventListener('cancel', event => event.preventDefault());
async function changeServerPorts(event) {
  event.preventDefault();
  const form = event.currentTarget;
  if (form.getAttribute('aria-busy') === 'true') return;
  const fileInput = form.elements.filePort, webInput = form.elements.webPort;
  const expectedFilePort = Number(fileInput.defaultValue);
  const expectedWebPort = webInput.defaultValue ? Number(webInput.defaultValue) : null;
  const filePort = fileInput.valueAsNumber;
  const webPort = webInput.disabled ? expectedWebPort : webInput.valueAsNumber;
  const webPortChanged = webPort !== expectedWebPort;
  const error = $('#ports-error'), dialog = $('#web-restarting');
  error.textContent = '';
  if (filePort === webPort) {
    error.textContent = 'Choose a different port for each listener.';
    fileInput.focus();
    return;
  }
  if (!webPortChanged && filePort === expectedFilePort) { toast('The listening ports are unchanged.'); return; }
  setBusy(form, true);
  fileInput.readOnly = webInput.readOnly = true;
  if (webPortChanged) {
    $('#restart-port').textContent = webPort;
    dialog.showModal();
  }
  try {
    const saved = await api('/server/ports', 'POST', { filePort, webPort, expectedFilePort, expectedWebPort });
    if (webPortChanged) {
      // The server acknowledges only after the new listener is ready.
      if (saved?.webPort !== webPort) throw new Error('Could not confirm the new web UI port. Reopen the console from the server tray icon.');
      const destination = new URL(location.href);
      destination.port = String(webPort);
      location.replace(destination.href);
      return;
    }
    if (state) {
      state.filePort = saved.filePort;
      fileInput.defaultValue = String(saved.filePort);
      const hint = $('#connection-host-hint');
      if (hint) hint.textContent = `Use an address the client can reach on port ${saved.filePort}.`;
      updateConnectionLink();
      updateInviteLink();
    }
    toast('File service port updated.');
  } catch (exception) {
    if (dialog.open) dialog.close();
    const message = webPortChanged && exception.cause
      ? 'The server did not confirm the port change. Use the BijouShare Server tray icon to open the current web UI.'
      : exception.message;
    if (error.isConnected) {
      error.textContent = message;
      if (webPortChanged) webInput.focus();
    } else toast(message);
  } finally {
    fileInput.readOnly = webInput.readOnly = false;
    setBusy(form, false);
  }
}

async function changePassword(event) {
  event.preventDefault();
  const form = event.currentTarget, values = new FormData(form);
  $('#password-error').textContent = '';
  if (values.get('newPassword') !== values.get('confirmation')) {
    $('#password-error').textContent = 'The new passwords do not match.'; form.elements.confirmation.focus(); return;
  }
  setBusy(form, true);
  try {
    await api('/admin/password', 'POST', { currentPassword: values.get('currentPassword'), newPassword: values.get('newPassword') });
    form.reset(); toast('Password updated. Sign in again.'); showLogin(); await session();
  } catch (error) { if ($('#password-error')) $('#password-error').textContent = error.message; else toast(error.message); }
  finally { if (form.isConnected) setBusy(form, false); }
}

async function startSession() {
  const button = $('#retry-session'); button.disabled = true;
  try {
    const result = await session(); button.hidden = true;
    if (result.setupRequired) showSetup(); else if (result.authenticated) await enter(); else showLogin();
    $('#login-error').textContent = '';
  } catch (error) { showLogin(); $('#login-error').textContent = error.message; button.hidden = false; }
  finally { button.disabled = false; }
}
$('#retry-session').addEventListener('click', startSession);
startSession();
