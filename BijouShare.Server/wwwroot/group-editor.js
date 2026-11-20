'use strict';

const expandedGroups = new Set();
const groupEdits = new Map();

function resetGroupWorkspace() {
  expandedGroups.clear();
  groupEdits.clear();
}

function groupCount(count, noun) {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

function groupButton(action, label, options = {}) {
  return `<button type="button" class="${options.style ?? 'quiet'}" data-group-action="${action}"${options.ruleId ? ` data-rule-id="${escapeHtml(options.ruleId)}"` : ''}${options.disabled ? ' disabled' : ''}>${label}</button>`;
}

function groupShares(groupId, ruleId) {
  const assigned = new Set(state.rules.filter(rule => rule.groupId === groupId && rule.id !== ruleId).map(rule => rule.shareId));
  return state.shares.filter(share => !assigned.has(share.id));
}

function groupNameForm(edit, creating) {
  return `<form class="group-name-form" data-group-form="name" aria-label="${creating ? 'Create' : 'Rename'} group">
    <label><span class="sr-only">Group name</span><input name="groupName" value="${escapeHtml(edit.name)}" placeholder="Group name" maxlength="100" autocomplete="off" required></label>
    <button class="primary" type="submit">${creating ? 'Create group' : 'Save name'}</button>${groupButton('cancel', 'Cancel')}</form>`;
}

function targetName(target) {
  return target.isAggregate ? target.name + ' (built-in)' : target.name;
}

function ruleSummary(rule, editing) {
  const share = state.shares.find(share => share.id === rule.shareId);
  return `<section class="group-rule" aria-label="${escapeHtml(targetName(share))} permissions">
    <div class="group-rule-heading"><h3>${icon('folder')}${escapeHtml(targetName(share))}${share.enabled ? '' : '<span class="pill off">Disabled</span>'}</h3>
    <div class="group-actions">${groupButton('edit-rule', 'Edit rule', {ruleId: rule.id, disabled: editing})}${groupButton('delete-rule', 'Delete rule', {ruleId: rule.id, disabled: editing})}</div></div>
    <ul class="group-path-list">${[rule, ...rule.additionalScopes].map(scope => `<li><div><strong>${escapeHtml(scope.path || (share.isAggregate ? 'Every share root' : 'Share root'))}</strong><small>${scope.inherit ? 'Includes descendants' : 'This path only'}</small></div>
    <div><small>Allow</small> ${escapeHtml(permissionText(scope.allow))}</div><div><small>Deny</small> ${escapeHtml(permissionText(scope.deny))}</div></li>`).join('')}</ul></section>`;
}

function ruleOptions(items, id) {
  return items.map(item => `<option value="${escapeHtml(item.id)}"${item.id === id ? ' selected' : ''}>${escapeHtml(targetName(item))}${item.enabled === false ? ' (disabled)' : ''}</option>`).join('');
}

function permissionMatrix(scope) {
  const split = Math.ceil(state.permissions.length / 2);
  return `<div class="group-matrix">${[state.permissions.slice(0, split), state.permissions.slice(split)].map(permissions =>
    `<table><caption class="sr-only">Path permissions</caption><thead><tr><th scope="col">Permission</th><th scope="col">Allow</th><th scope="col">Deny</th></tr></thead><tbody>${permissions.map(permission => {
      const label = escapeHtml(permissionLabels[permission.name] ?? permission.name);
      return `<tr><th scope="row">${label}</th>${['allow', 'deny'].map(mask => `<td><input type="checkbox" name="${mask}" value="${permission.value}" aria-label="${mask === 'allow' ? 'Allow' : 'Deny'} ${label}"${scope[mask] & permission.value ? ' checked' : ''}></td>`).join('')}</tr>`;
    }).join('')}</tbody></table>`).join('')}</div>`;
}

function ruleForm(groupId, edit) {
  const scope = edit.scopes[edit.index];
  const shares = groupShares(groupId, edit.id);
  const invalidTarget = !shares.some(share => share.id === edit.shareId);
  const aggregate = shares.some(share => share.id === edit.shareId && share.isAggregate);
  return `<form class="group-rule-form" data-group-form="rule" aria-label="${edit.existing ? 'Edit' : 'Add'} permission rule">
    <div class="group-rule-fields"><label>Share<select name="ruleShare" required>${invalidTarget ? '<option value="">Choose a share</option>' : ''}${ruleOptions(shares, edit.shareId)}</select></label></div>
    <div class="group-scope-editor"><div class="group-scope-nav"><h3>Paths</h3><div class="group-scope-list" role="group" aria-label="Permission paths">${edit.scopes.map((item, index) =>
      `<button type="button" data-group-action="scope" data-scope-index="${index}" aria-pressed="${index === edit.index}"><strong>${escapeHtml(item.path || (aggregate ? 'Every share root' : 'Share root'))}</strong><small>${item.inherit ? 'Includes descendants' : 'This path only'}</small></button>`).join('')}</div>${aggregate ? '' : groupButton('add-path', `${icon('plus')}Add path`)}</div>
    <div class="group-scope-fields"><div class="group-scope-heading">${aggregate ? '' : `<label>Relative path<input name="rulePath" value="${escapeHtml(scope.path)}" maxlength="2048" placeholder="Share root" spellcheck="false"></label>`}
    ${edit.scopes.length > 1 ? groupButton('remove-path', 'Remove path') : ''}</div><p class="hint">${aggregate ? 'This rule applies to every current and future share. Select an individual share to set permissions on a specific path.' : 'Leave empty for the share root. Separate folders with /.'}</p>
    <label class="check"><input type="checkbox" name="descendants"${scope.inherit ? ' checked' : ''}>Include files and folders below this path</label>
    <div class="group-presets" role="group" aria-label="Replace path permissions"><span>Presets</span>${[['read','Read only'],['write','Read and write'],['full','Full control'],['clear','Clear']].map(([value, label]) =>
      `<button type="button" data-group-action="preset" data-preset-value="${value}"${value === 'write' ? ' title="Includes creating and editing. Excludes delete and rename."' : ''}>${label}</button>`).join('')}</div>
    ${permissionMatrix(scope)}</div></div>
    <div class="group-actions group-save">${groupButton('cancel', 'Cancel')}<button class="primary" type="submit"${invalidTarget ? ' disabled' : ''}>Save rule</button></div></form>`;
}

function groupDeletion(group, rules, edit, members) {
  const isGroup = edit.kind === 'delete-group';
  const invites = state.invites.filter(invite => invite.groupIds.includes(group.id)).length;
  const rule = rules.find(rule => rule.id === edit.id);
  const share = state.shares.find(share => share.id === rule?.shareId);
  const name = isGroup ? group.name : share ? targetName(share) : 'share';
  const detail = isGroup
    ? `Deleting this group removes ${groupCount(rules.length, 'rule')} and its membership from ${groupCount(members, 'device')} and ${groupCount(invites, 'invite')}.`
    : 'Removing a deny can grant access through another matching rule.';
  return `<form class="group-confirm" data-group-form="delete"><div><strong>Delete ${escapeHtml(name)}${isGroup ? '' : ' rule'}?</strong><p>${detail}</p></div><div class="group-actions">${groupButton('cancel', 'Cancel')}<button type="submit" class="destructive">Delete ${isGroup ? 'group' : 'rule'}</button></div></form>`;
}

function renderGroup(group) {
  const id = escapeHtml(group.id);
  const rules = state.rules.filter(rule => rule.groupId === group.id);
  const members = state.devices.filter(device => device.groupIds.includes(group.id)).length;
  const edit = groupEdits.get(group.id);
  const open = expandedGroups.has(group.id);
  const admin = group.isAdministrator;
  const addingRule = edit?.kind === 'rule' && !edit.existing;
  let detail = '';
  if (open) {
    if (admin) detail = '<p class="group-note">Administrator grants full control on every enabled share. Matching denies from other groups still take precedence.</p>';
    else {
      const shares = groupShares(group.id);
      detail = `<div class="group-rule-heading"><h3>Share permissions</h3>${groupButton('add-rule', `${icon('plus')}Add rule`, { disabled: Boolean(edit) || !shares.length })}</div>`;
      if (!rules.length && !addingRule) detail += '<p class="group-note">This group has no share permissions.</p>';
      if (addingRule) detail += ruleForm(group.id, edit);
      for (const rule of rules) {
        if (edit?.kind === 'rule' && edit.id === rule.id) detail += ruleForm(group.id, edit);
        else {
          detail += ruleSummary(rule, Boolean(edit));
          if (edit?.kind === 'delete-rule' && edit.id === rule.id) detail += groupDeletion(group, rules, edit, members);
        }
      }
      if (edit?.kind === 'delete-group') detail += groupDeletion(group, rules, edit, members);
    }
  }
  return `<fieldset class="group-entry" data-group-key="${id}"${edit?.busy ? ' disabled aria-busy="true"' : ''}><legend class="sr-only">${escapeHtml(group.name)}</legend>
    <div class="group-row">${edit?.kind === 'name' ? groupNameForm(edit, false) :
      `<button type="button" class="group-toggle" data-group-action="toggle" aria-expanded="${open}" aria-controls="group-detail-${id}">${icon('chevron')}<strong>${escapeHtml(group.name)}</strong></button>`}
    <span class="group-counts">${groupCount(members, 'device')} <span aria-hidden="true">·</span> ${admin ? 'Full control' : groupCount(rules.length, 'rule')}</span>
    ${admin ? `<span class="group-permanent">${icon('lock')}Permanent</span>` : `<div class="group-actions">${edit?.kind === 'name' ? '' : groupButton('rename', 'Rename', {disabled: Boolean(edit)})}${groupButton('delete-group', 'Delete', {disabled: Boolean(edit)})}</div>`}</div>
    <div class="group-detail" id="group-detail-${id}" ${open ? '' : 'hidden'}>${detail}</div>${groupError(edit)}</fieldset>`;
}

function groupError(edit) {
  return `<p class="group-error error" role="alert">${escapeHtml(edit?.error)}</p>`;
}

function renderGroupWorkspace() {
  const groups = new Set(state.groups.map(group => group.id));
  for (const id of expandedGroups) if (!groups.has(id)) expandedGroups.delete(id);
  for (const [key, draft] of groupEdits) {
    if (key === 'new' || draft.busy) continue;
    const referencesRule = draft.kind === 'delete-rule' || (draft.kind === 'rule' && draft.existing);
    if (!groups.has(key) || (referencesRule && !state.rules.some(rule => rule.id === draft.id && rule.groupId === key))) {
      groupEdits.delete(key);
    }
  }
  const edit = groupEdits.get('new');
  return heading('Groups', 'Manage share access for each group. Matching deny rules take precedence over allows.',
    groupButton('new', `${icon('plus')}Add group`, {style: 'primary', disabled: Boolean(edit)})) +
    `<div class="panel group-workspace">${edit ? `<fieldset class="group-entry group-create" data-group-key="new"${edit.busy ? ' disabled aria-busy="true"' : ''}><legend class="sr-only">New group</legend>${groupNameForm(edit, true)}${groupError(edit)}</fieldset>` : ''}
    ${state.groups.map(renderGroup).join('')}</div>`;
}

function refreshGroupEditor(key, focus) {
  if (!state || tab !== 'groups') return;
  const selector = `[data-group-key="${CSS.escape(key)}"]`;
  const current = groupsContent.querySelector(selector);
  const group = state.groups.find(group => group.id === key);
  const previousList = current?.querySelector('.group-scope-list');
  const top = previousList?.scrollTop ?? 0, left = previousList?.scrollLeft ?? 0;
  if (current && group) current.outerHTML = renderGroup(group);
  else groupsContent.innerHTML = renderGroupWorkspace();
  const row = groupsContent.querySelector(selector);
  const list = row?.querySelector('.group-scope-list');
  if (list) {
    list.scrollTop = top;
    list.scrollLeft = left;
    const selected = list.querySelector('[aria-pressed="true"]').getBoundingClientRect();
    const viewport = list.getBoundingClientRect();
    list.scrollTop += Math.min(0, selected.top - viewport.top) + Math.max(0, selected.bottom - viewport.bottom);
    list.scrollLeft += Math.min(0, selected.left - viewport.left) + Math.max(0, selected.right - viewport.right);
  }
  const target = row?.querySelector(focus || '[data-group-action="toggle"]') ?? document.querySelector('[data-group-action="new"]');
  target?.focus();
  if (target?.name === 'groupName') target.select();
}

function startRule(key, rule) {
  const empty = {path: '', inherit: true, allow: 0, deny: 0};
  const scopes = rule ? [rule, ...rule.additionalScopes].map(({path, inherit, allow, deny}) => ({path, inherit, allow, deny})) : [empty];
  const available = groupShares(key);
  return {kind: 'rule', existing: Boolean(rule), id: rule?.id ?? crypto.randomUUID(),
    shareId: rule?.shareId ?? (available.length === 1 && !available[0].isAggregate ? available[0].id : ''), scopes, index: 0};
}

function applyGroupPreset(scope, preset) {
  const read = ['ListDirectory', 'ReadData', 'ReadAttributes', 'ReadPermissions'];
  const write = ['WriteData', 'CreateFiles', 'CreateDirectories', 'WriteAttributes'];
  scope.allow = state.permissions.filter(permission => preset === 'full' || (preset !== 'clear' && read.includes(permission.name)) ||
    (preset === 'write' && write.includes(permission.name))).reduce((mask, permission) => mask | permission.value, 0);
  scope.deny = 0;
}

const groupsContent = document.getElementById('content');
groupsContent.addEventListener('click', event => {
  const button = event.target.closest('button[data-group-action]');
  if (!button || button.disabled || tab !== 'groups') return;
  const action = button.dataset.groupAction;
  const key = button.closest('[data-group-key]')?.dataset.groupKey ?? 'new';
  const group = state.groups.find(group => group.id === key);
  const edit = groupEdits.get(key);
  if (edit?.busy) return;
  let focus = '[data-group-action="toggle"]';
  switch (action) {
    case 'toggle':
      if (expandedGroups.has(key)) expandedGroups.delete(key); else expandedGroups.add(key);
      break;
    case 'new':
    case 'rename':
      groupEdits.set(key, {kind: 'name', id: group?.id ?? crypto.randomUUID(), name: group?.name ?? ''});
      focus = '[name="groupName"]';
      break;
    case 'cancel':
      groupEdits.delete(key);
      if (edit.kind === 'name') focus = '[data-group-action="rename"]';
      else if (edit.kind === 'rule' || edit.kind === 'delete-rule') focus = edit.existing || edit.kind === 'delete-rule'
        ? `[data-group-action="edit-rule"][data-rule-id="${CSS.escape(edit.id)}"]` : '[data-group-action="add-rule"]';
      else focus = '[data-group-action="delete-group"]';
      break;
    case 'delete-group':
    case 'delete-rule':
      groupEdits.set(key, {kind: action, id: button.dataset.ruleId ?? key});
      expandedGroups.add(key);
      focus = '.group-confirm [data-group-action="cancel"]';
      break;
    case 'add-rule':
    case 'edit-rule':
      groupEdits.set(key, startRule(key, state.rules.find(rule => rule.id === button.dataset.ruleId)));
      focus = '[name="ruleShare"]';
      break;
    case 'scope':
      edit.index = Number(button.dataset.scopeIndex);
      focus = '[data-group-action="scope"][aria-pressed="true"]';
      break;
    case 'add-path':
      edit.scopes.push({path: '', inherit: true, allow: 0, deny: 0});
      edit.index = edit.scopes.length - 1;
      focus = '[name="rulePath"]';
      break;
    case 'remove-path':
      edit.scopes.splice(edit.index, 1);
      edit.index = Math.min(edit.index, edit.scopes.length - 1);
      focus = '[name="rulePath"]';
      break;
    case 'preset':
      applyGroupPreset(edit.scopes[edit.index], button.dataset.presetValue);
      focus = `[data-preset-value="${button.dataset.presetValue}"]`;
      break;
    default: return;
  }
  refreshGroupEditor(key, focus);
});

groupsContent.addEventListener('input', event => {
  const input = event.target;
  const row = input.closest('[data-group-key]');
  if (!row) return;
  const key = row.dataset.groupKey;
  const edit = groupEdits.get(key);
  if (!edit || edit.busy) return;
  if (input.name === 'groupName') edit.name = input.value;
  if (edit.kind !== 'rule') return;
  const scope = edit.scopes[edit.index];
  const current = row.querySelector('[data-group-action="scope"][aria-pressed="true"]');
  switch (input.name) {
    case 'rulePath': scope.path = input.value; current.querySelector('strong').textContent = scope.path || 'Share root'; break;
    case 'descendants': scope.inherit = input.checked; current.querySelector('small').textContent = scope.inherit ? 'Includes descendants' : 'This path only'; break;
    case 'ruleShare': {
      const target = state.shares.find(share => share.id === input.value);
      if (target?.isAggregate && (edit.scopes.length > 1 || edit.scopes[0].path)) {
        input.value = edit.shareId;
        row.querySelector('.group-error').textContent = 'To switch this rule to All, remove additional paths and clear the relative path first.';
        break;
      }
      edit.shareId = input.value;
      refreshGroupEditor(key, '[name="ruleShare"]');
      break;
    }
    case 'allow':
    case 'deny': {
      const bit = Number(input.value);
      scope[input.name] = input.checked ? scope[input.name] | bit : scope[input.name] & ~bit;
      if (input.checked) {
        const other = input.name === 'allow' ? 'deny' : 'allow';
        scope[other] &= ~bit;
        input.closest('tr').querySelector(`[name="${other}"]`).checked = false;
      }
      break;
    }
  }
});

groupsContent.addEventListener('keydown', event => {
  if (event.key === 'Escape' && event.target.closest('.group-name-form')) {
    event.preventDefault();
    event.target.closest('form').querySelector('[data-group-action="cancel"]').click();
  }
});

groupsContent.addEventListener('submit', async event => {
  const form = event.target.closest('[data-group-form]');
  if (!form) return;
  event.preventDefault();
  const row = form.closest('[data-group-key]');
  const key = row.dataset.groupKey;
  const edit = groupEdits.get(key);
  if (!edit || edit.busy) return;
  edit.busy = row.disabled = true;
  row.setAttribute('aria-busy', 'true');
  row.querySelector('.group-error').textContent = '';
  let savedKey = key;
  let message;
  try {
    if (edit.kind === 'name') {
      const name = edit.name.trim();
      if (!name) throw new Error('Enter a group name.');
      await api(`/groups/${edit.id}`, 'PUT', {id: edit.id, name});
      savedKey = edit.id;
      message = key === 'new' ? 'Group created.' : 'Group renamed.';
    } else if (edit.kind === 'rule') {
      const [first, ...additionalScopes] = edit.scopes;
      await api(`/rules/${edit.id}`, 'PUT', {id: edit.id, groupId: key, shareId: edit.shareId, ...first, additionalScopes});
      message = 'Permissions saved.';
    } else {
      const entity = edit.kind === 'delete-group' ? 'groups' : 'rules';
      await api(`/${entity}/${edit.id}`, 'DELETE');
      message = entity === 'groups' ? 'Group deleted.' : 'Permission rule deleted.';
    }
  } catch (error) {
    edit.busy = false;
    edit.error = error.message;
    if (state && tab === 'groups' && groupEdits.get(key) === edit) {
      refreshGroupEditor(key, form.dataset.groupForm === 'rule' ? '[name="rulePath"]' : form.dataset.groupForm === 'name' ? '[name="groupName"]' : '.group-confirm button');
    }
    return;
  }
  if (groupEdits.get(key) !== edit) return;
  groupEdits.delete(key);
  if (edit.kind === 'delete-group') expandedGroups.delete(key);
  else if (key === 'new' || edit.kind === 'rule') expandedGroups.add(savedKey);
  try {
    await reload();
    if (state && tab === 'groups') refreshGroupEditor(savedKey);
    toast(message);
  } catch (error) {
    if (state && tab === 'groups') refreshGroupEditor(key);
    toast(`${message} Refresh to load the latest changes. ${error.message}`);
  }
});
