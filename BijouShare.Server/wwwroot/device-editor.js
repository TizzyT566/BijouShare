'use strict';

const deviceWorkspace = (() => {
  const drafts = new Map();
  let expanded = null;
  const keyFor = (kind, device) => kind + '-' + device.id;
  const fingerprintOf = device => device.fingerprint || device.publicIdentity || '';
  const devicesFor = kind => kind === 'pending' ? state.pendingDevices : state.devices;
  const content = document.querySelector('#content');

  function reset() {
    drafts.clear();
    expanded = null;
  }

  function getDraft(key, device) {
    let draft = drafts.get(key);
    if (!draft) {
      draft = { fingerprint: fingerprintOf(device), rejected: device.rejected, groups: new Map(), enabled: null, busy: false, error: '', filter: '' };
      drafts.set(key, draft);
    }
    return draft;
  }

  function selectedGroups(device, draft) {
    const saved = new Set(device.groupIds || []);
    return state.groups.filter(group => draft.groups.get(group.id) ?? saved.has(group.id));
  }

  function editor(kind, device, key, draft) {
    const pending = kind === 'pending';
    const inviteRequired = pending && state.inviteOnly;
    const safeKey = escapeHtml(key);
    const enabled = draft.enabled ?? device.enabled;
    const selected = new Set(selectedGroups(device, draft).map(group => group.id));
    const filterable = state.groups.length > 12;
    const query = filterable ? draft.filter.trim().toLocaleLowerCase() : '';
    const matches = group => group.name.toLocaleLowerCase().includes(query);
    const choices = state.groups.map(group => `<label data-group-option ${matches(group) ? '' : 'hidden'}><input type="checkbox" name="group" value="${escapeHtml(group.id)}" ${selected.has(group.id) ? 'checked' : ''}><span>${escapeHtml(group.name)}</span></label>`).join('');
    const blocked = pending ? device.rejected : !device.enabled;
    const action = blocked ? 'Forget' : 'Block';
    const deviceAction = `<button type="button" class="quiet danger device-block" ${blocked ? 'data-remove-record' : 'data-delete'}="${pending ? 'pendingDevices' : 'devices'}" data-id="${escapeHtml(device.id)}" aria-label="${action} device ${escapeHtml(device.name)}">${action} device</button>`;
    return `<form class="device-form" id="device-panel-${safeKey}" data-device-form="${safeKey}" data-kind="${kind}" data-id="${escapeHtml(device.id)}" aria-labelledby="device-name-${safeKey}" aria-busy="${draft.busy}">
      <fieldset class="device-inputs" ${draft.busy ? 'disabled' : ''}><legend class="sr-only">${pending ? 'Device approval' : 'Device settings'}</legend>
        <div class="device-fields">
          ${inviteRequired ? '' : `<fieldset class="device-memberships"><legend>Group memberships</legend>
            ${filterable ? `<input class="device-filter" type="search" name="group-filter" aria-label="Filter groups" placeholder="Filter groups" autocomplete="off" value="${escapeHtml(draft.filter)}" aria-controls="device-choices-${safeKey}">` : ''}
            <div class="device-checklist" id="device-choices-${safeKey}" role="region" tabindex="0" aria-label="Available groups">${choices || '<span class="muted">No groups available.</span>'}
              ${filterable ? `<span class="muted device-no-match" role="status" ${state.groups.some(matches) ? 'hidden' : ''}>No matching groups.</span>` : ''}</div>
            <p class="hint">Devices with no groups have no share access.</p>
            <p class="hint" data-admin-hint ${state.groups.some(group => group.isAdministrator && selected.has(group.id)) ? '' : 'hidden'}>Administrator grants full control on enabled shares. Explicit denies from other groups take precedence.</p>
          </fieldset>`}
          <div class="device-details">
            ${pending ? '' : `<label class="device-enabled"><input type="checkbox" name="enabled" ${enabled ? 'checked' : ''}>Enabled</label>`}
            <dl><div><dt>Device fingerprint</dt><dd class="mono">${escapeHtml(formattedFingerprint(draft.fingerprint))}</dd></div>
            <div><dt>Device record ID</dt><dd class="mono">${escapeHtml(device.id)}</dd></div>
            ${pending ? `<div><dt>First request</dt><dd>${timeText(device.firstSeenUtc)}</dd></div><div><dt>Last request</dt><dd>${timeText(device.lastSeenUtc)}</dd></div>` : ''}</dl>
          </div>
        </div>
        <p class="error" role="alert">${escapeHtml(draft.error)}</p>
        <div class="device-form-actions">${deviceAction}<button type="button" class="quiet" data-device-cancel>Cancel</button>
          ${inviteRequired ? '' : `<button type="submit" class="primary">${pending ? 'Approve device' : 'Save changes'}</button>`}</div>
      </fieldset>
    </form>`;
  }

  function section(kind, label, devices) {
    if (!devices.length)
      return `<section class="panel device-section"><div class="panel-title"><h2>${label}</h2><span>0</span></div><p class="device-empty">${kind === 'pending' ? 'No device requests.' : 'No approved devices.'}</p></section>`;
    const rows = devices.map(device => {
      const key = keyFor(kind, device), safeKey = escapeHtml(key);
      const open = expanded === key, pending = kind === 'pending';
      const groups = (device.groupIds || []).map(id => nameOf(state.groups, id));
      const status = pending ? device.rejected ? 'Blocked' : state.inviteOnly ? 'Invite required' : 'Awaiting approval'
        : device.enabled ? 'Enabled' : 'Blocked';
      const summary = pending ? '' : groups.length ? groups.slice(0, 2).join(', ') + (groups.length > 2 ? ' +' + (groups.length - 2) : '') : 'No groups';
      return `<article class="device-row" data-${pending ? 'pending' : 'device'}-id="${escapeHtml(device.id)}">
        <button type="button" id="device-name-${safeKey}" class="device-toggle" data-device-expand="${safeKey}" aria-expanded="${open}" ${open ? `aria-controls="device-panel-${safeKey}"` : ''} aria-labelledby="device-label-${safeKey}" aria-describedby="device-status-${safeKey}${summary ? ' device-groups-' + safeKey : ''}">
          ${icon('chevron')}<strong id="device-label-${safeKey}">${escapeHtml(device.name)}</strong><span class="device-summary" id="device-groups-${safeKey}">${escapeHtml(summary)}</span>
          <span class="pill ${status === 'Blocked' ? 'off' : ''}" id="device-status-${safeKey}">${status}</span>
        </button>
        ${open ? editor(kind, device, key, getDraft(key, device)) : ''}
      </article>`;
    }).join('');
    return `<section class="panel device-section"><div class="panel-title"><h2>${label}</h2><span>${devices.length}</span></div>${rows}</section>`;
  }

  function renderPage() {
    const known = new Map();
    for (const kind of ['pending', 'approved'])
      for (const device of devicesFor(kind)) known.set(keyFor(kind, device), device);
    for (const [key, draft] of drafts) {
      const device = known.get(key);
      if (device && draft.fingerprint === fingerprintOf(device) && draft.rejected === device.rejected) continue;
      drafts.delete(key);
      if (expanded === key) expanded = null;
    }
    const hint = state.inviteOnly ? 'Invite-only enrollment is on. New devices need a valid invite link.' +
      (state.pendingDevices.some(device => !device.rejected) ? ' Devices with earlier requests can enroll using an invite.' : '')
      : 'Select a device to manage its access groups or review its request.';
    return heading('Devices', hint) +
      '<div class="device-workspace">' + section('pending', 'Device requests', state.pendingDevices) + section('approved', 'Approved devices', state.devices) + '</div>';
  }

  function toggle(key) {
    if (drafts.get(expanded)?.busy) return;
    expanded = expanded === key ? null : key;
    render();
    document.getElementById('device-name-' + key)?.focus({ preventScroll: true });
  }

  content.addEventListener('click', event => {
    const button = event.target.closest('button');
    if (!button) return;
    if (button.dataset.deviceExpand) toggle(button.dataset.deviceExpand);
    if (button.hasAttribute('data-device-cancel')) {
      const key = button.closest('form').dataset.deviceForm;
      drafts.delete(key);
      toggle(key);
    }
  });

  content.addEventListener('change', event => {
    const input = event.target, form = input.closest('form[data-device-form]');
    if (!form || input.type !== 'checkbox') return;
    const draft = drafts.get(form.dataset.deviceForm);
    const device = devicesFor(form.dataset.kind).find(item => item.id === form.dataset.id);
    if (!draft || !device || draft.busy) return;
    if (input.name === 'enabled') draft.enabled = input.checked === device.enabled ? null : input.checked;
    if (input.name === 'group') {
      if (input.checked === (device.groupIds || []).includes(input.value)) draft.groups.delete(input.value);
      else draft.groups.set(input.value, input.checked);
      if (state.groups.some(group => group.id === input.value && group.isAdministrator))
        form.querySelector('[data-admin-hint]').hidden = !input.checked;
    }
    draft.error = '';
    form.querySelector('[role="alert"]').textContent = '';
  });

  content.addEventListener('input', event => {
    const input = event.target;
    if (input.name !== 'group-filter') return;
    const form = input.closest('form[data-device-form]');
    const draft = form && drafts.get(form.dataset.deviceForm);
    if (!draft || draft.busy) return;
    draft.filter = input.value;
    const query = input.value.trim().toLocaleLowerCase();
    const choices = form.querySelector('.device-checklist');
    let any = false;
    for (const label of choices.querySelectorAll('[data-group-option]')) {
      label.hidden = !label.textContent.trim().toLocaleLowerCase().includes(query);
      if (!label.hidden) any = true;
    }
    choices.querySelector('.device-no-match').hidden = any;
    choices.scrollTop = 0;
  });

  content.addEventListener('submit', async event => {
    const form = event.target.closest('form[data-device-form]');
    if (!form) return;
    event.preventDefault();
    const { deviceForm: key, kind, id } = form.dataset;
    const draft = drafts.get(key), device = devicesFor(kind).find(item => item.id === id);
    if (!draft || !device || draft.busy || draft.fingerprint !== fingerprintOf(device)) return;
    const pending = kind === 'pending';
    if (pending && state.inviteOnly) return;
    const groupIds = selectedGroups(device, draft).map(group => group.id);
    const enabled = draft.enabled ?? device.enabled;
    const message = pending ? 'Device approved. It can connect on its next attempt.' : 'Device changes saved.';
    draft.busy = true;
    draft.error = '';
    form.setAttribute('aria-busy', 'true');
    form.querySelector('fieldset').disabled = true;
    form.querySelector('[role="alert"]').textContent = '';
    try {
      if (pending) await api(`/pending-devices/${encodeURIComponent(id)}/approve`, 'POST', { groupIds, fingerprint: draft.fingerprint });
      else await api(`/devices/${encodeURIComponent(id)}`, 'PUT', { enabled, groupIds });
    } catch (error) {
      if (drafts.get(key) !== draft) return;
      draft.busy = false;
      draft.error = error.message;
      if (tab === 'devices' && expanded === key) {
        render();
        document.getElementById('device-panel-' + key)?.querySelector('[type="submit"]')?.focus({ preventScroll: true });
      }
      return;
    }
    if (drafts.get(key) !== draft) return;
    // Keep an acknowledged mutation visible if reloading the full server state fails.
    if (pending) {
      state.pendingDevices = state.pendingDevices.filter(item => item.id !== id);
      if (!state.devices.some(item => item.id === id))
        state.devices.push({ id, name: device.name, fingerprint: draft.fingerprint, publicIdentity: draft.fingerprint, enabled: true, groupIds });
    } else {
      const current = state.devices.find(item => item.id === id);
      if (current) Object.assign(current, { enabled, groupIds });
    }
    drafts.delete(key);
    if (expanded === key) expanded = null;
    render();
    const epoch = viewEpoch;
    try {
      await reload();
      if (epoch === viewEpoch) toast(message);
    } catch (error) {
      if (epoch === viewEpoch) toast(message + ' Refresh failed. ' + error.message);
    }
    if (tab === 'devices' && epoch === viewEpoch && document.activeElement === document.body)
      document.getElementById('device-name-approved-' + id)?.focus({ preventScroll: true });
  });

  return { renderPage, reset, editing: () => expanded !== null };
})();

function renderDeviceWorkspace() { return deviceWorkspace.renderPage(); }
function resetDeviceWorkspace() { deviceWorkspace.reset(); }
function deviceWorkspaceEditing() { return deviceWorkspace.editing(); }
