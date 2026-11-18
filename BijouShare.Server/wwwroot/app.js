'use strict';

const $ = selector => document.querySelector(selector);
const tabs = ['overview', 'groups', 'shares', 'permissions', 'devices', 'invites', 'activity', 'settings'];
const entityNames = { groups: 'group', shares: 'share', rules: 'permission rule', devices: 'device', pendingDevices: 'device request', invites: 'invite' };
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
const empty = (title, text) => `<div class="empty"><strong>${escapeHtml(title)}</strong>${escapeHtml(text)}</div>`;
const heading = (title, text, action = '') => `<div class="page-heading"><div><h1 tabindex="-1">${title}</h1><p class="muted">${text}</p></div>${action}</div>`;
const newButton = (label, entity, reason = '') => `<button class="primary" data-new="${entity}" ${reason ? `disabled title="${escapeHtml(reason)}"` : ''}>+ ${label}</button>`;
const serverFolderName = () => `${state.serverName}_${state.serverId.slice(0, 16)}`;

function isLoopbackAddress(host) {
  try {
    const authority = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
    const name = new URL(`http://${authority}`).hostname.toLowerCase().replace(/^\[|\]$/g, '');
    return name === 'localhost' || name.endsWith('.localhost') || name === '::1' || name.startsWith('127.') || name.startsWith('::ffff:7f');
  } catch { return false; }
}

function renderServerIdentity() {
  return `<div class="panel server-identity" aria-label="Server identity"><div class="panel-title"><h2>${escapeHtml(state.serverName)}</h2><span>SERVER IDENTITY</span></div><dl><div><dt>Server ID · name and public-key hash</dt><dd class="mono server-id">${escapeHtml(state.serverId)}</dd></div><div><dt>Folder on the client drive · first 16 ID characters</dt><dd><code class="server-folder-name">${escapeHtml(serverFolderName())}</code></dd></div></dl><p class="hint">The server name is chosen during setup in this web UI. Its full ID is SHA-256 of the server name followed by its persistent public key; the drive folder uses its first 16 characters. Restarts and administrator password changes keep it.</p></div>`;
}

function connectionUri(host, code = '') {
  if (!host || host !== host.trim() || /[\s@/?#\\%]/.test(host) || host.length > 253) throw new Error('Enter the server LAN hostname or IP, without a port or path.');
  const authority = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host;
  let parsed;
  try { parsed = new URL(`http://${authority}:${state.filePort}`); }
  catch { throw new Error('Enter a valid server LAN hostname or IP.'); }
  if (!parsed.hostname || parsed.username || parsed.password || parsed.pathname !== '/') throw new Error('Enter the server hostname or IP only.');
  return `wad://${parsed.hostname}:${state.filePort}${code ? '/' + encodeURIComponent(code) : ''}`;
}

function renderConnectionLink() {
  let uri = '';
  try { uri = connectionUri(connectionHost); } catch { /* Let the address field display a validation error. */ }
  return `<div class="panel connection-panel"><div class="panel-title"><h2>Connect a client</h2><span>ONE SHARED DRIVE</span></div><p class="muted">Open a server link on a client with BijouShare installed. Its drive stays mounted while the device waits for approval. <a href="#invites">Create an invite</a> to approve new devices automatically.</p><label for="connection-host">Server LAN hostname or IP</label><input id="connection-host" value="${escapeHtml(connectionHost)}" maxlength="253" autocomplete="off" spellcheck="false" aria-describedby="connection-host-hint${isLoopbackAddress(connectionHost) ? ' connection-local-warning' : ''}"><p id="connection-host-hint" class="hint">Use an address reachable from the client. The file connection uses port ${state.filePort}.</p><p id="connection-local-warning" class="address-warning" role="status" ${isLoopbackAddress(connectionHost) ? '' : 'hidden'}>This address points to the client itself. Enter the server’s LAN address to share this link with another device.</p><div class="connection-actions"><a id="connection-link" class="button-link" ${uri ? `href="${escapeHtml(uri)}"` : ''}>Open BijouShare</a><button type="button" data-copy-connection>Copy link</button></div><output id="connection-uri" class="mono">${escapeHtml(uri)}</output><p id="connection-error" class="error" role="alert"></p></div>`;
}

function actions(entity, item) {
  const name = entity === 'rules'
    ? `${nameOf(state.groups, item.groupId)} / ${nameOf(state.shares, item.shareId)} / ${item.path || 'share root'}`
    : item.name;
  const remove = entity === 'devices' ? 'Block' : entity === 'shares' ? 'Remove' : 'Delete';
  return `<div class="actions"><button class="quiet" data-edit="${entity}" data-id="${item.id}" aria-label="Edit ${entityNames[entity]} ${escapeHtml(name)}">Edit</button>${entity === 'devices' && !item.enabled ? '' : `<button class="quiet danger" data-delete="${entity}" data-id="${item.id}" aria-label="${remove} ${entityNames[entity]} ${escapeHtml(name)}">${remove}</button>`}</div>`;
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
    if (error.name === 'AbortError') throw new Error('The server did not respond in time. Refresh its state before retrying a change.');
    if (error instanceof TypeError) throw new Error('Cannot reach the server. Check the connection and refresh its state before retrying a change.');
    throw error;
  } finally { clearTimeout(timeout); }
}

async function session() {
  const result = await api('/session');
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
    !$('#editor').open && !$('#confirmation').open && !$('#invite-result').open && !document.activeElement?.closest('#content');
}
setInterval(async () => {
  if (devicePollBusy || !canRefreshDevices()) return;
  devicePollBusy = true;
  const epoch = viewEpoch, sequence = ++stateLoadSequence;
  try {
    const updated = await api('/state');
    if (epoch !== viewEpoch || sequence !== stateLoadSequence || !canRefreshDevices()) return;
    const changed = JSON.stringify([state.devices, state.pendingDevices, state.invites, state.groups, state.serverName, state.serverId]) !==
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
window.addEventListener('hashchange', () => { if (state) render(); });

function permissionText(mask) {
  const all = state.permissions.reduce((value, permission) => value | permission.value, 0);
  if (mask === all) return 'Full control';
  if (!mask) return 'None';
  return state.permissions.filter(permission => (mask & permission.value) !== 0)
    .map(permission => permissionLabels[permission.name] ?? permission.name).join(', ');
}

function renderOverview() {
  const { groups, shares, rules, devices, pendingDevices } = state;
  const statistics = [
    ['Shared locations', shares.length, 'Files, folders, and drives'],
    ['Pending devices', pendingDevices.filter(device => !device.rejected).length, 'Waiting for approval'],
    ['Access groups', groups.length, `${rules.length} permission rules`],
    ['Approved devices', devices.length, `${devices.filter(device => device.enabled).length} enabled devices`]
  ];
  return heading('A place for every file.', 'Manage shared storage and the devices that can access it.', newButton('Add a share', 'shares')) +
    renderServerIdentity() +
    renderConnectionLink() +
    `<div class="stats">${statistics.map(([title, count, description]) => `<div class="stat"><span>${title}</span><strong>${count}</strong><small>${description}</small></div>`).join('')}</div>` +
    (pendingDevices.some(device => !device.rejected) ? `<div class="callout approval-notice"><div><strong>New device requests are awaiting approval.</strong>Review the devices and assign their access groups.</div><a class="button-link" href="#devices">Review requests</a></div>` : '') +
    renderSharesTable('Shared locations') +
    `<div class="panel"><div class="panel-title"><h2>Set up access in three steps</h2><span>DENY BY DEFAULT</span></div><div class="steps"><div><span class="step-no">01 / AUTHORIZE</span><h3>Create groups and permissions</h3><p>Choose what each group can do on a share, folder, or file. Denies always take precedence.</p></div><div><span class="step-no">02 / CONNECT</span><h3>Connect a client</h3><p>Run the client once to choose its device name and shared drive letter, then open a server link.</p></div><div><span class="step-no">03 / APPROVE</span><h3>Assign device groups</h3><p>Approve the device and select its groups, or send an invite with those groups already selected.</p></div></div></div>`;
}

function renderSharesTable(title = '') {
  return table(['Name on virtual drive', 'Server path', 'Status', ''], state.shares.map(share =>
    `<tr><td><strong>${escapeHtml(share.name)}</strong></td><td class="mono">${escapeHtml(share.localPath)}</td><td>${enabled(share.enabled)}</td><td>${actions('shares', share)}</td></tr>`), title, 'Add a file, folder, or drive to begin sharing.');
}

function renderGroups() {
  return heading('Groups', 'A shared set of permissions for the devices that need them.', newButton('Add group', 'groups')) +
    table(['Group', 'Members', 'Permission rules', ''], state.groups.map(group =>
      `<tr><td><strong>${escapeHtml(group.name)}</strong></td><td>${state.devices.filter(device => device.groupIds.includes(group.id)).length} devices</td><td>${state.rules.filter(rule => rule.groupId === group.id).length} rules</td><td>${actions('groups', group)}</td></tr>`));
}

function renderPermissions() {
  const missing = !state.groups.length || !state.shares.length;
  return heading('Permissions', 'Server-enforced access for every file and folder.', newButton('Add rule', 'rules', missing ? 'Create a group and a share first.' : '')) +
    `<div class="callout"><strong>Group grants combine. Explicit denies take precedence.</strong>Paths are relative to a share. An empty path means the share root. Inherited rules apply to all descendants.${missing ? '<br>Create a group and a share before adding a permission rule.' : ''}</div>` +
    table(['Group / share', 'Relative path', 'Allow', 'Deny', 'Inheritance', ''], state.rules.map(rule =>
      `<tr><td><strong>${escapeHtml(nameOf(state.groups, rule.groupId))}</strong><small>${escapeHtml(nameOf(state.shares, rule.shareId))}</small></td><td class="mono">${escapeHtml(rule.path || '/')}</td><td>${escapeHtml(permissionText(rule.allow))}</td><td>${escapeHtml(permissionText(rule.deny))}</td><td>${rule.inherit ? 'This path + descendants' : 'This path only'}</td><td>${actions('rules', rule)}</td></tr>`));
}

const formattedFingerprint = value => String(value ?? '').match(/.{1,8}/g)?.join(' ') ?? '';
function fingerprintDetails(device) {
  return `<details class="key-details"><summary>View fingerprints</summary><p>Client identity · SHA-256</p><code class="fingerprint">${escapeHtml(formattedFingerprint(device.fingerprint))}</code><p>Server identity for this device · SHA-256</p><code class="fingerprint">${escapeHtml(formattedFingerprint(device.serverFingerprint))}</code></details>`;
}

const deviceGroups = device => device.groupIds.map(id => `<span class="pill">${escapeHtml(nameOf(state.groups, id))}</span>`).join(' ') || '<span class="muted">No groups — no access</span>';
const timeText = value => `<time datetime="${escapeHtml(value)}">${escapeHtml(new Date(value).toLocaleString())}</time>`;

function renderDevices() {
  return heading('Devices', 'Clients request access automatically. Approve each device and assign its groups.') +
    `<div class="callout"><strong>New client? Open its server connection link.</strong>Use the link on the Overview page, or <a href="#invites">create an invite</a> for automatic approval into selected groups. Its device name, ID, and public key will appear below. After approval, its shares appear beneath <code>${escapeHtml(serverFolderName())}</code> on the client drive. This list refreshes automatically while idle; use Refresh to check immediately.</div>` +
    table(['Device / ID', 'Client identity', 'First / last request', 'Status', ''], state.pendingDevices.map(device =>
      `<tr data-pending-id="${device.id}"><td><strong>${escapeHtml(device.name)}</strong><small class="mono">${escapeHtml(device.id)}</small></td><td><code class="fingerprint">${escapeHtml(formattedFingerprint(device.fingerprint))}</code></td><td>${timeText(device.firstSeenUtc)}<small>Last: ${timeText(device.lastSeenUtc)}</small></td><td><span class="pill ${device.rejected ? 'denied' : ''}">${device.rejected ? 'Blocked' : 'Awaiting approval'}</span></td><td><div class="actions"><button class="primary" data-approve="${device.id}" aria-label="Approve ${escapeHtml(device.name)}">Approve</button>${device.rejected ? '' : `<button class="quiet danger" data-delete="pendingDevices" data-id="${device.id}" aria-label="Block ${escapeHtml(device.name)}">Block</button>`}</div></td></tr>`), 'Device requests', 'No devices are waiting. New clients appear here when they connect.') +
    table(['Device / ID', 'Group memberships', 'Identity fingerprints', 'Status', ''], state.devices.map(device =>
      `<tr data-device-id="${device.id}"><td><strong>${escapeHtml(device.name)}</strong><small class="mono">${escapeHtml(device.id)}</small></td><td>${deviceGroups(device)}</td><td>${fingerprintDetails(device)}</td><td><span class="pill ${device.enabled ? '' : 'off'}">${device.enabled ? 'Enabled' : 'Blocked'}</span></td><td>${actions('devices', device)}</td></tr>`), 'Approved devices', 'Approve a pending device to grant access through its groups.');
}

function inviteStatus(invite) {
  if (invite.revoked) return 'Revoked';
  if (invite.expiresUtc && new Date(invite.expiresUtc).getTime() <= Date.now()) return 'Expired';
  if (invite.maxUses !== null && invite.uses >= invite.maxUses) return 'Used up';
  return 'Active';
}

function renderInvites() {
  return heading('Invites', 'Automatically approve new devices into the groups you choose.', newButton('Create invite', 'invites')) +
    `<div class="callout"><strong>Each invite grants its selected group memberships.</strong>Set a use limit and an expiration, or allow unlimited uses and no expiration. Existing devices keep their current groups; blocked devices remain blocked. Copy each new code when it is created.</div>` +
    table(['Invite', 'Groups', 'Uses', 'Expires', 'Status', ''], (state.invites ?? []).map(invite => {
      const status = inviteStatus(invite);
      return `<tr data-invite-id="${invite.id}"><td><strong>${escapeHtml(invite.name)}</strong><small>Created ${timeText(invite.createdUtc)}</small></td><td>${deviceGroups(invite)}</td><td>${invite.maxUses === null ? `${invite.uses} used · unlimited` : `${invite.uses} of ${invite.maxUses} used`}<small>${invite.maxUses === null ? 'No use limit' : Math.max(0, invite.maxUses - invite.uses) + ' remaining'}</small></td><td>${invite.expiresUtc ? timeText(invite.expiresUtc) : 'Never'}</td><td><span class="pill ${status === 'Active' ? '' : 'off'}">${status}</span></td><td>${invite.revoked ? '' : `<button class="quiet danger" data-delete="invites" data-id="${invite.id}" aria-label="Revoke invite ${escapeHtml(invite.name)}">Revoke</button>`}</td></tr>`;
    }), 'Enrollment invites', 'Create an invite and share its link with the devices you want to enroll.');
}

function renderActivity() {
  return heading('Activity', 'Recent connections, file changes, and administrative actions.') +
    table(['Time', 'Actor', 'Action', 'Target', 'Result'], state.activity.map(event =>
      `<tr><td><time datetime="${escapeHtml(event.time)}">${escapeHtml(new Date(event.time).toLocaleString())}</time></td><td>${escapeHtml(event.actor)}</td><td>${escapeHtml(event.action)}</td><td class="mono">${escapeHtml(event.target)}</td><td><span class="pill ${event.result === 'OK' ? '' : 'denied'}">${escapeHtml(event.result)}</span></td></tr>`), 'Recent events', 'Events appear here as the server is used.') +
    '<p class="hint">The latest 200 retained audit events are shown. Complete daily audit files are stored on the server.</p>';
}

function renderSettings() {
  return heading('Settings', 'Manage administrator access to this server.') +
    renderServerIdentity() +
    renderConnectionLink() +
    `<div class="panel"><div class="panel-title"><h2>Change administrator password</h2></div><form id="password-form" class="password-form">
      <label>Current password<input name="currentPassword" type="password" autocomplete="current-password" required maxlength="1024"></label>
      <label>New password<input name="newPassword" type="password" autocomplete="new-password" minlength="14" maxlength="1024" required aria-describedby="password-hint"></label>
      <label>Confirm new password<input name="confirmation" type="password" autocomplete="new-password" minlength="14" maxlength="1024" required></label>
      <span class="hint" id="password-hint">At least 14 characters. Changing it ends existing administrator sessions.</span><p id="password-error" class="error" role="alert"></p><button type="submit" class="primary">Update password</button></form></div>`;
}

function render() {
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
  if (pendingCount) {
    if (!badge) { badge = document.createElement('span'); badge.className = 'nav-badge'; deviceLink.append(badge); }
    badge.textContent = pendingCount; badge.setAttribute('aria-label', `${pendingCount} pending device ${pendingCount === 1 ? 'request' : 'requests'}`);
  } else if (badge) badge.remove();
  $('#server-name').textContent = state.serverName;
  $('#server-name').title = serverFolderName();
  $('#crumb').textContent = label; document.title = `${state.serverName} · ${label} · BijouShare`;
  const renderers = {
    overview: renderOverview, groups: renderGroups,
    shares: () => heading('Shares', 'Files, folders, and entire drives, together under one virtual drive.', newButton('Add share', 'shares')) + renderSharesTable(),
    permissions: renderPermissions, devices: renderDevices, invites: renderInvites, activity: renderActivity, settings: renderSettings
  };
  $('#content').innerHTML = renderers[tab]();
  $('#password-form')?.addEventListener('submit', changePassword);
}

function field(name, label, value = '', hint = '') {
  const id = `editor-${name}`;
  return `<label for="${id}">${label}</label><input id="${id}" name="${name}" value="${escapeHtml(value)}" required maxlength="${name === 'localPath' || name === 'path' ? '2048' : '100'}" ${hint ? `aria-describedby="${id}-hint"` : ''}>${hint ? `<span class="hint" id="${id}-hint">${hint}</span>` : ''}`;
}

function select(name, label, items, value, prefix = 'editor') {
  const id = `${prefix}-${name}`;
  return `<label for="${id}">${label}</label><select id="${id}" name="${name}" required><option value="" disabled ${value ? '' : 'selected'}>Choose ${label.toLowerCase()}</option>${items.map(item => `<option value="${item.id}" ${item.id === value ? 'selected' : ''}>${escapeHtml(item.name)}${item.enabled === false ? ' (disabled)' : ''}</option>`).join('')}</select>`;
}

function groupFields(groupIds = []) {
  return `<fieldset class="memberships"><legend>Group memberships</legend><div class="check-grid">${state.groups.map(group => `<label class="check"><input type="checkbox" name="group" value="${group.id}" ${groupIds.includes(group.id) ? 'checked' : ''}>${escapeHtml(group.name)}</label>`).join('') || '<p class="hint">Create a group and its permissions to grant access.</p>'}</div></fieldset><p class="hint">Access comes only from these groups. No groups means no file access. Matching deny rules override allows from every group.</p>`;
}

function approveDevice(id) {
  const device = state.pendingDevices.find(item => item.id === id);
  if (!device) return;
  openEditor(`Approve ${device.name}`,
    `<p class="hint">${device.rejected ? 'This removes the block and approves this device.' : 'This device will be allowed to connect on its next attempt.'}</p><div class="identity-preview"><strong>${escapeHtml(device.name)}</strong><small>Device ID: ${escapeHtml(device.id)}</small><p>Client identity · SHA-256</p><code class="fingerprint">${escapeHtml(formattedFingerprint(device.fingerprint))}</code></div>` + groupFields(),
    async form => {
      const values = new FormData(form);
      await api(`/pending-devices/${id}/approve`, 'POST', { groupIds: values.getAll('group'), fingerprint: device.fingerprint });
      return 'Device approved. It can connect on its next attempt.';
    }, 'Approve device');
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
  openEditor('Create invite', field('name', 'Invite name', '', 'A label for keeping track of this invitation.') + groupFields() +
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

function edit(entity, id) {
  if (entity === 'invites') { createInvite(); return; }
  const existing = state[entity].find(item => item.id === id);
  const item = existing ?? { id: crypto.randomUUID(), enabled: true, groupIds: [], allow: 0, deny: 0, inherit: true };
  let fields = '';
  if (entity === 'groups') fields = field('name', 'Name', item.name);
  if (entity === 'shares') fields = field('name', 'Name on virtual drive', item.name) + field('localPath', 'Absolute server path', item.localPath, 'Examples: D:\\, D:\\Team, or D:\\Reports\\summary.pdf');
  if (entity === 'devices') fields = `<p class="hint">${escapeHtml(item.name)} · ${escapeHtml(item.id)}</p>` + groupFields(item.groupIds);
  if (entity === 'rules') {
    fields = select('groupId', 'Group', state.groups, item.groupId) + select('shareId', 'Share', state.shares, item.shareId) +
      field('path', 'Relative path', item.path, 'Leave empty for the share root. Use / between folder names.') +
      `<div class="permission-presets" role="group" aria-label="Permission presets"><button type="button" class="quiet" data-preset="read">Read only</button><button type="button" class="quiet" data-preset="write">Read and write</button><button type="button" class="quiet" data-preset="full">Full control</button><button type="button" class="quiet" data-preset="clear">Clear</button></div><p class="hint">Presets replace the selections below. Read and write excludes delete and rename.</p><div class="permission-grid title"><span>FUNCTIONALITY</span><span>ALLOW</span><span>DENY</span></div>` +
      state.permissions.map(permission => `<div class="permission-grid"><span>${escapeHtml(permissionLabels[permission.name] ?? permission.name)}</span><input type="checkbox" name="allow" value="${permission.value}" aria-label="Allow ${escapeHtml(permissionLabels[permission.name] ?? permission.name)}" ${(item.allow & permission.value) ? 'checked' : ''}><input type="checkbox" name="deny" value="${permission.value}" aria-label="Deny ${escapeHtml(permissionLabels[permission.name] ?? permission.name)}" ${(item.deny & permission.value) ? 'checked' : ''}></div>`).join('') +
      `<label class="check"><input type="checkbox" name="inherit" ${item.inherit ? 'checked' : ''}>Apply to all files and folders below this path</label>`;
  }
  if (['shares', 'devices'].includes(entity)) fields += `<label class="check"><input type="checkbox" name="enabled" ${item.enabled ? 'checked' : ''}>Enabled</label>`;
  openEditor(`${existing ? 'Edit' : 'Add'} ${entityNames[entity]}`, fields, async form => {
    const values = new FormData(form);
    let value = { id: item.id };
    if (entity === 'groups') value = { ...value, name: values.get('name').trim() };
    if (entity === 'shares') value = { ...value, name: values.get('name').trim(), localPath: values.get('localPath').trim(), enabled: values.has('enabled') };
    if (entity === 'devices') value = { groupIds: values.getAll('group'), enabled: values.has('enabled') };
    if (entity === 'rules') value = {
      ...value, groupId: values.get('groupId'), shareId: values.get('shareId'), path: values.get('path').trim(), inherit: values.has('inherit'),
      allow: values.getAll('allow').reduce((mask, bit) => mask | Number(bit), 0), deny: values.getAll('deny').reduce((mask, bit) => mask | Number(bit), 0)
    };
    if ('name' in value && !value.name) throw new Error('Enter a name with at least one non-space character.');
    await api(`/${entity}/${item.id}`, 'PUT', value);
    return 'Changes saved.';
  });
  if (entity === 'rules') $('#editor-fields input[name=path]').required = false;
}

function applyPreset(preset) {
  const read = ['ListDirectory', 'ReadData', 'ReadAttributes', 'ReadPermissions'];
  const selected = preset === 'full' ? state.permissions.map(permission => permission.name)
    : preset === 'write' ? [...read, 'WriteData', 'CreateFiles', 'CreateDirectories', 'WriteAttributes'] : preset === 'read' ? read : [];
  const mask = state.permissions.filter(permission => selected.includes(permission.name)).reduce((value, permission) => value | permission.value, 0);
  $('#editor-form').querySelectorAll('input[name=allow]').forEach(input => { input.checked = (mask & Number(input.value)) !== 0; });
  $('#editor-form').querySelectorAll('input[name=deny]').forEach(input => { input.checked = false; });
}
$('#editor-form').addEventListener('change', event => {
  const input = event.target;
  if (!input.matches('input[name=allow], input[name=deny]') || !input.checked) return;
  $(`#editor-form input[name=${input.name === 'allow' ? 'deny' : 'allow'}][value="${input.value}"]`).checked = false;
});

function confirmDeletion(entity, id) {
  const item = state[entity].find(value => value.id === id);
  const name = item.name ?? `${nameOf(state.groups, item.groupId)} / ${nameOf(state.shares, item.shareId)} / ${item.path || '/'}`;
  let title = `Delete ${entityNames[entity]}?`, detail = '', button = 'Delete';
  if (entity === 'groups') detail = `This removes the group from ${state.devices.filter(device => device.groupIds.includes(id)).length} device(s) and deletes ${state.rules.filter(rule => rule.groupId === id).length} permission rule(s). Their effective access may change.`;
  if (entity === 'shares') { title = 'Remove share?'; button = 'Remove share'; detail = `Clients will lose this shared location and ${state.rules.filter(rule => rule.shareId === id).length} permission rule(s) will be removed. The server’s files remain in place.`; }
  if (entity === 'rules') detail = 'Removing this rule changes effective access for its group. Removing a deny can grant access through other matching rules.';
  if (entity === 'devices') { title = 'Block device?'; button = 'Block device'; detail = 'This device loses access immediately. Its identity and groups are retained. Enable it in Edit to allow it to reconnect without reenrollment.'; }
  if (entity === 'pendingDevices') { title = 'Block device?'; button = 'Block device'; detail = 'This device stays blocked when it retries. It will receive no file access unless you explicitly approve it later.'; }
  if (entity === 'invites') { title = 'Revoke invite?'; button = 'Revoke invite'; detail = 'This code will no longer enroll devices. Devices already enrolled keep their current groups and permissions.'; }
  $('#confirmation-title').textContent = title; $('#confirmation-name').textContent = name;
  $('#confirmation-detail').textContent = detail; $('#confirm-delete').textContent = button;
  $('#confirmation-error').textContent = ''; pendingDeletion = { entity, id };
  $('#confirmation').showModal(); $('#cancel-deletion').focus();
}
$('#confirm-delete').addEventListener('click', async () => {
  if (!pendingDeletion) return;
  const { entity, id } = pendingDeletion;
  const message = entity === 'devices' || entity === 'pendingDevices' ? 'Device blocked.' : entity === 'shares' ? 'Share removed.' : entity === 'invites' ? 'Invite revoked.' : 'Item deleted.';
  let deleted = false;
  setBusy($('#confirmation-form'), true);
  try {
    await api(`/${entity === 'pendingDevices' ? 'pending-devices' : entity}/${id}`, 'DELETE'); deleted = true; $('#confirmation').close(); pendingDeletion = null;
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
  if (button.dataset.new) edit(button.dataset.new);
  else if (button.dataset.edit) edit(button.dataset.edit, button.dataset.id);
  else if (button.dataset.delete) confirmDeletion(button.dataset.delete, button.dataset.id);
  else if (button.dataset.approve) approveDevice(button.dataset.approve);
  else if (button.dataset.preset) applyPreset(button.dataset.preset);
  else if (button.hasAttribute('data-copy-connection')) copyField('#connection-uri', 'Server link');
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
$('#close-editor').addEventListener('click', closeEditor);
$('#cancel-editor').addEventListener('click', closeEditor);
$('#editor').addEventListener('cancel', event => { if (editorBusy) event.preventDefault(); });

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
