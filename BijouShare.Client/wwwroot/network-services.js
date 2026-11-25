'use strict';

const networkServiceView = (() => {
  const rows = new Map();
  let active = false, generation = 0, busy = false, polling = false, timer;

  function showError(message) {
    document.querySelector('#listener-error-text').textContent = message;
    const dialog = document.querySelector('#listener-error');
    if (!dialog.open) dialog.showModal();
  }

  function makeRow() {
    const form = document.createElement('form');
    form.className = 'network-service-row';
    form.noValidate = true;
    form.innerHTML = '<div class="network-service-info"><h2></h2><p class="muted"></p><span class="network-service-state"></span></div>' +
      '<label>Local port<input type="text" inputmode="numeric" maxlength="5" autocomplete="off" required></label>' +
      '<button type="submit"></button>';
    const row = {form, input:form.querySelector('input'), button:form.querySelector('button')};
    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (busy) return;
      const service = row.service;
      const value = row.input.value.trim();
      if (!service.enabled && (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535)) {
        row.input.focus();
        showError('Enter a whole port number from 1 through 65535.');
        return;
      }
      busy = true;
      generation++;
      row.button.disabled = true;
      row.input.disabled = true;
      try {
        render(await api('/network-services', 'POST', {serverId:service.serverId, shareId:service.shareId,
          enabled:!service.enabled, localPort:service.enabled ? service.localPort : Number(value)}));
      } catch (error) { showError(error.message); }
      finally { busy = false; row.button.disabled = false; row.input.disabled = row.service.enabled; }
    });
    return row;
  }

  function render(snapshot) {
    const list = document.querySelector('#network-service-list'), seen = new Set();
    for (const [index, service] of snapshot.services.entries()) {
      const key = service.serverId + '/' + service.shareId;
      seen.add(key);
      let row = rows.get(key);
      if (!row) { row = makeRow(); rows.set(key, row); }
      if (list.children[index] !== row.form) list.insertBefore(row.form, list.children[index] ?? null);
      if (!row.service || service.enabled || row.service.enabled)
        row.input.value = service.localPort ?? service.suggestedPort ?? '';
      row.service = service;
      row.form.querySelector('h2').textContent = service.name;
      const access = [service.send && 'Send', service.receive && 'Receive'].filter(Boolean).join(' + ');
      row.form.querySelector('.muted').textContent = [service.serverName, String(service.protocol).toLowerCase() === 'both' ? 'TCP + UDP' : String(service.protocol).toUpperCase(), access].filter(Boolean).join(' · ');
      row.form.querySelector('.network-service-state').textContent = service.error || (service.listening ? 'Listening on 127.0.0.1:' + service.localPort : service.enabled ? 'Waiting to reconnect' : 'Stopped');
      row.input.disabled = service.enabled;
      row.button.classList.toggle('primary', !service.enabled);
      row.button.textContent = service.enabled ? 'Stop listener' : 'Start listener';
    }
    for (const [key, row] of rows) if (!seen.has(key)) { row.form.remove(); rows.delete(key); }
    const empty = document.querySelector('#network-empty');
    empty.textContent = 'No network services are available from your connected servers.';
    empty.hidden = seen.size > 0;
    const warnings = (snapshot.servers ?? []).filter(s => s.error).map(s => s.serverName + ' · ' + s.error);
    const status = document.querySelector('#network-catalog-status');
    status.textContent = warnings.join('\n');
    status.hidden = !warnings.length;
  }

  async function refresh() {
    if (!active || document.hidden || busy || polling) return;
    const sequence = generation;
    polling = true;
    try {
      const next = await api('/network-services');
      if (active && sequence === generation) render(next);
    } catch (error) {
      if (active && sequence === generation) {
        const status = document.querySelector('#network-catalog-status');
        status.textContent = error.message;
        status.hidden = false;
      }
    } finally { polling = false; }
  }
  document.addEventListener('visibilitychange', refresh);
  return {show(visible) {
    if (visible === active) return;
    active = visible;
    generation++;
    clearInterval(timer);
    if (active) { void refresh(); timer = setInterval(refresh, 4000); }
  }};
})();
