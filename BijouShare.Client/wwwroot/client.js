'use strict';
const $ = selector => document.querySelector(selector);
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
let state, csrf = '', busy = false, setupStep = 1, selectedRemoval = null, toastTimer;
let serverSignature = '', stateSequence = 0, initializedSettings = false;
const descriptions = {
  PendingApproval: ['Awaiting approval', 'An administrator must approve this device and choose its groups.', 'waiting'],
  DeviceRejected: ['Blocked', 'An administrator must explicitly approve this device before it can connect.', 'blocked'],
  DeviceBlocked: ['Blocked', 'An administrator must enable this device before it can connect.', 'blocked'],
  InvalidInvite: ['Invite unavailable', 'The invite is invalid, expired, revoked, or has no uses remaining. Ask for a new link.', 'blocked'],
  InviteUnsupported: ['Server update required', 'This server does not support invite enrollment. Ask its administrator to update it or approve this device manually.', 'blocked'],
  InviteInvalid: ['Invite unavailable', 'The invite is invalid, expired, revoked, or has no uses remaining. Ask for a new link.', 'blocked'],
  InviteExpired: ['Invite expired', 'Ask the server administrator for a new invitation.', 'blocked'],
  InviteExhausted: ['Invite used up', 'Ask the server administrator for a new invitation.', 'blocked'],
  ServerIdentityChanged: ['Server identity changed', 'The pinned server key no longer matches. Verify the change with the administrator before resetting trust.', 'blocked'],
  ServerIdentityConflict: ['Server identity conflict', 'A shortened folder ID conflicts with another server. Access remains blocked.', 'blocked'],
  ServerUpgradeRequired: ['Server update required', 'This server needs an update before it can appear on the drive.', 'blocked'],
  AuthenticationFailed: ['Authentication failed', 'The server could not prove its identity. Check the endpoint with its administrator.', 'blocked'],
  HybridUnavailable: ['Windows update required', 'This Windows installation does not provide native ML-KEM support. Hybrid encryption is required; update Windows before connecting.', 'blocked'],
  ConfigurationError: ['Configuration error', 'The client could not access or save its configuration. Check the service account and data directory.', 'blocked'],
  Disconnected: ['Offline', 'Its drive folder is temporarily hidden. Retrying automatically; other connected servers stay available.', ''],
  Waiting: ['Connecting', 'Waiting for an authenticated connection.', 'waiting']
};

async function api(path, method = 'GET', body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const response = await fetch('/api' + path, {method, credentials:'same-origin', signal:controller.signal,
      headers:{'Content-Type':'application/json','X-CSRF-TOKEN':csrf}, body:body === undefined ? undefined : JSON.stringify(body)});
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status}). Refresh and try again.`);
    return result;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('The client did not respond in time. Refresh before retrying.');
    if (error instanceof TypeError) throw new Error('Cannot reach the client service. Start BijouShare on this computer, then refresh.');
    throw error;
  } finally { clearTimeout(timer); }
}

function driveOptions(select, current, letters) {
  const choices = [...new Set([...(current ? [current] : []), ...letters])].sort();
  select.replaceChildren(...choices.map(letter => {const option = document.createElement('option'); option.value = letter; option.textContent = letter; return option;}));
  select.value = choices.includes(current) ? current : choices[0] || '';
}
function setSetupStep(step) {
  setupStep = step;
  $('#setup-name-step').hidden = step !== 1;
  $('#setup-drive-step').hidden = step !== 2;
  $('#step-one').classList.toggle('current', step === 1);
  $('#step-two').classList.toggle('current', step === 2);
  $('#step-one').toggleAttribute('aria-current', step === 1);
  $('#step-two').toggleAttribute('aria-current', step === 2);
  if (step === 1) $('#step-one').setAttribute('aria-current', 'step');
  else $('#step-two').setAttribute('aria-current', 'step');
  $('.steps').setAttribute('aria-label', `Setup progress: step ${step} of 2`);
  (step === 1 ? $('#setup-name') : $('#setup-drive')).focus();
}
function validateName(input) {
  input.setCustomValidity(input.value !== input.value.trim() || /[\u0000-\u001f\u007f]/.test(input.value) ? 'Use a name without surrounding whitespace or control characters.' : '');
  return input.reportValidity();
}
function render(next) {
  state = next;
  $('#service-notice').hidden = true;
  $('#loading').hidden = true;
  $('#setup').hidden = state.setupComplete;
  $('#dashboard').hidden = !state.setupComplete;
  if (!state.setupComplete) {
    if (!$('#setup-name').value) $('#setup-name').value = state.deviceName;
    const chosen = $('#setup-drive').value || state.mountPoint;
    if (document.activeElement !== $('#setup-drive')) driveOptions($('#setup-drive'), state.availableDriveLetters.includes(chosen) ? chosen : null, state.availableDriveLetters);
    $('#finish-setup').disabled = state.availableDriveLetters.length === 0 || busy;
    $('#setup-pending').hidden = state.servers.length === 0;
    $('#setup-pending').textContent = state.servers.length ? `${state.servers.length} server connection${state.servers.length === 1 ? '' : 's'} will start after setup: ${state.servers.map(server => server.host + ':' + server.port).join(', ')}` : '';
    return;
  }
  $('#sidebar-name').textContent = state.deviceName;
  $('#device-id').textContent = state.deviceId;
  document.title = `${state.deviceName} · BijouShare`;
  $('#drive-letter').textContent = (state.mountedPoint || state.mountPoint).replace('\\', '');
  $('#drive-status').textContent = state.driveError ? 'Needs attention' : state.mountedPoint ? 'Mounted' : 'Starting…';
  $('#drive-notice').hidden = !state.restartRequired && !state.driveError;
  $('#drive-notice').textContent = state.driveError || (state.restartRequired ? `${state.mountPoint} is saved. Restart the client service to move the shared drive from ${state.mountedPoint}.` : '');
  $('#connected-count').textContent = `${state.servers.filter(server => server.connected).length} connected`;
  if (!initializedSettings) {
    $('#device-name').value = state.deviceName;
    driveOptions($('#device-drive'), state.mountPoint, state.availableDriveLetters);
    initializedSettings = true;
  } else if (document.activeElement !== $('#device-drive')) {
    const selected = $('#device-drive').value;
    const available = [...state.availableDriveLetters, state.mountPoint];
    driveOptions($('#device-drive'), available.includes(selected) ? selected : state.mountPoint, available);
  }
  const signature = JSON.stringify([state.servers, state.mountedPoint || state.mountPoint]);
  if (signature !== serverSignature) {
    serverSignature = signature;
    const openDetails = new Set([...$('#server-list').querySelectorAll('.server-card details[open]')].map(details => {
      const card = details.closest('.server-card'); return `${card.dataset.host}\n${card.dataset.port}`;
    }));
    const focusedControl = document.activeElement?.closest('#server-list [data-remove], #server-list summary');
    const focusedCard = focusedControl?.closest('.server-card');
    const focusedKey = focusedCard ? `${focusedCard.dataset.host}\n${focusedCard.dataset.port}` : null;
    const focusSelector = focusedControl?.matches('summary') ? 'summary' : '[data-remove]';
    $('#server-list').innerHTML = state.servers.length ? state.servers.map(server => {
      const [label, detail, style] = server.connected ? ['Connected', 'Shared folders are available using this device’s group permissions.', 'connected'] : (descriptions[server.error] || descriptions.Waiting);
      return `<article class="panel server-card" data-host="${escapeHtml(server.host)}" data-port="${server.port}"><div><span class="status ${style}">${label}</span><h2>${escapeHtml(server.serverName || server.host)}</h2><p class="server-endpoint">${escapeHtml(server.host)}:${server.port}</p>${server.folderName ? `<p class="folder"><code>${escapeHtml(state.mountedPoint || state.mountPoint)}${escapeHtml(server.folderName)}\\</code>${server.connected ? '' : '<span class="folder-note">Available when connected</span>'}</p>` : ''}<p class="server-description">${escapeHtml(detail)}</p>${server.fingerprint ? `<details${openDetails.has(`${server.host}\n${server.port}`) ? ' open' : ''}><summary>Verified server identity</summary><p>${escapeHtml(server.fingerprint)}</p></details>` : ''}</div><button type="button" data-remove="true" data-host="${escapeHtml(server.host)}" data-port="${server.port}" aria-label="Disconnect ${escapeHtml(server.serverName || server.host)}">Disconnect</button></article>`;
    }).join('') : '<div class="empty"><strong>Your drive is ready.</strong><p>Connect your first server to add its folder here.</p><p>The shared drive stays mounted while this list is empty.</p></div>';
    if (focusedKey) [...$('#server-list').querySelectorAll('.server-card')]
      .find(card => `${card.dataset.host}\n${card.dataset.port}` === focusedKey)?.querySelector(focusSelector)?.focus({preventScroll:true});
  }
}
async function reload() {
  const sequence = ++stateSequence;
  const next = await api('/state');
  if (sequence === stateSequence) render(next);
}
function toast(message) {
  clearTimeout(toastTimer); $('#toast').textContent = message; $('#toast').hidden = false;
  toastTimer = setTimeout(() => {$('#toast').hidden = true;}, 5500);
}
async function submit(form, errorSelector, operation) {
  if (busy) return;
  busy = true;
  $(errorSelector).textContent = '';
  const buttons = [...form.querySelectorAll('button')]; buttons.forEach(button => {button.disabled = true;});
  stateSequence++;
  try {await operation();} catch (error) {$(errorSelector).textContent = error.message;}
  finally {busy = false; buttons.forEach(button => {button.disabled = false;});}
}

$('#continue-setup').addEventListener('click', () => {if (validateName($('#setup-name'))) setSetupStep(2);});
$('#back-setup').addEventListener('click', () => setSetupStep(1));
$('#setup-name').addEventListener('input', () => $('#setup-name').setCustomValidity(''));
$('#device-name').addEventListener('input', () => $('#device-name').setCustomValidity(''));
$('#setup-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (setupStep === 1) {if (validateName($('#setup-name'))) setSetupStep(2); return;}
  if (!validateName($('#setup-name'))) {setSetupStep(1); return;}
  await submit(event.currentTarget, '#setup-error', async () => {
    render(await api('/device', 'PUT', {deviceName:$('#setup-name').value, mountPoint:$('#setup-drive').value}));
    toast('Your shared drive is ready. Connect a server to add its folder.');
    $('#server-link').focus();
  });
});
$('#add-server').addEventListener('submit', async event => {
  event.preventDefault();
  await submit(event.currentTarget, '#server-error', async () => {
    let uri = $('#server-link').value.trim();
    if (!uri.includes('://')) uri = 'wad://' + uri;
    const next = await api('/servers', 'POST', {uri});
    $('#server-link').value = ''; // Invite secrets are never retained in the server list or browser storage.
    render(next); toast('Server saved. Its folder appears after authentication and approval.');
  });
});
$('#device-form').addEventListener('submit', async event => {
  event.preventDefault(); if (!validateName($('#device-name'))) return;
  await submit(event.currentTarget, '#device-error', async () => {
    const next = await api('/device', 'PUT', {deviceName:$('#device-name').value, mountPoint:$('#device-drive').value});
    initializedSettings = false;
    render(next);
    toast(state.restartRequired ? 'Settings saved. Restart the client service to use the new drive letter.' : 'Device settings saved.');
  });
});
$('#refresh').addEventListener('click', async () => {
  const button = $('#refresh'); button.disabled = true;
  try {stateSequence++; render(await api('/refresh', 'POST')); toast('Connections refreshed.');}
  catch (error) {toast(error.message);} finally {button.disabled = false;}
});
$('#server-list').addEventListener('click', event => {
  const button = event.target.closest('[data-remove]'); if (!button) return;
  selectedRemoval = {host:button.dataset.host, port:Number(button.dataset.port)};
  $('#remove-name').textContent = selectedRemoval.host + ':' + selectedRemoval.port;
  $('#remove-error').textContent = ''; $('#remove-dialog').showModal(); $('#cancel-remove').focus();
});
$('#cancel-remove').addEventListener('click', () => {$('#remove-dialog').close(); selectedRemoval = null;});
$('#confirm-remove').addEventListener('click', async () => {
  if (!selectedRemoval || busy) return;
  await submit($('#remove-dialog'), '#remove-error', async () => {
    render(await api('/servers/remove', 'POST', selectedRemoval));
    $('#remove-dialog').close(); selectedRemoval = null; toast('Server disconnected. Your shared drive stays mounted.');
  });
});
async function start() {
  $('#retry-load').hidden = true;
  try {csrf = (await api('/session')).csrfToken; await reload();}
  catch (error) {$('#loading-message').textContent = error.message; $('#retry-load').hidden = false;}
}
$('#retry-load').addEventListener('click', start);
setInterval(async () => {
  if (busy || !state || document.hidden || $('#remove-dialog').open) return;
  try {await reload();} catch {
    if (state.setupComplete) {
      $('#service-notice').textContent = 'Cannot reach the client service. Connection status may be out of date; check that BijouShare is running.';
      $('#service-notice').hidden = false;
    }
  }
}, 3000);
start();
