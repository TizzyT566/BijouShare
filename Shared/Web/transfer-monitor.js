'use strict';

const transferNumber = new Intl.NumberFormat(undefined, {maximumFractionDigits: 2});
const transferBytes = new Intl.NumberFormat(undefined, {maximumFractionDigits: 0});

function formatTransferSize(bytes) {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'];
  let unit = 0;
  while (bytes >= 1024 && unit < units.length - 1) { bytes /= 1024; unit++; }
  return transferNumber.format(bytes) + ' ' + units[unit];
}

class TransferChart {
  constructor(host, title, {headingLevel = 2} = {}) {
    host.classList.add('transfer-chart');
    this.heading = document.createElement(headingLevel === 3 ? 'h3' : 'h2');
    const body = document.createElement('div');
    body.className = 'transfer-body';
    body.innerHTML = `<div class="transfer-history">
      <div class="transfer-axis"><span>Transfer speed</span><span data-ceiling>—</span></div>
      <svg viewBox="0 0 590 100" preserveAspectRatio="none" role="img" aria-label="Transfer speeds over the past 60 seconds">
        <polygon class="transfer-area"></polygon>
        <polyline class="transfer-line transfer-total"></polyline>
        <polyline class="transfer-line transfer-read"></polyline>
        <polyline class="transfer-line transfer-write"></polyline>
      </svg><div class="transfer-axis"><span>60 s ago</span><span>Now</span></div>
    </div>
    <table class="transfer-values" aria-label="Current speeds and cumulative file bytes">
      <thead><tr><th scope="col">Transfer</th><th scope="col">Current speed</th><th scope="col">Bytes transferred</th></tr></thead>
      <tbody>${['Read', 'Write', 'Total'].map(label => `<tr><th scope="row"><span class="transfer-swatch transfer-${label.toLowerCase()}" aria-hidden="true"></span>${label}</th><td>—</td><td>—</td></tr>`).join('')}</tbody>
    </table>`;
    host.replaceChildren(this.heading, body);
    this.setTitle(title);
    this.ceiling = body.querySelector('[data-ceiling]');
    this.area = body.querySelector('polygon');
    this.rows = Array.from(body.querySelectorAll('tbody tr'));
    this.lines = ['read', 'write', 'total'].map(key => body.querySelector('polyline.transfer-' + key));
  }

  setTitle(title) {
    if (this.heading.textContent !== title) this.heading.textContent = title;
  }

  update({readBytes, writeBytes, samples}) {
    const peak = samples.reduce((max, sample) => Math.max(max, sample.readBytes + sample.writeBytes), 0);
    if (peak === 0 && this.idle && this.readBytes === readBytes && this.writeBytes === writeBytes) return;
    this.idle = peak === 0;
    this.readBytes = readBytes;
    this.writeBytes = writeBytes;
    const last = samples.at(-1);
    const readRate = last?.readBytes ?? 0, writeRate = last?.writeBytes ?? 0;
    const current = [readRate, writeRate, readRate + writeRate];
    const readTotal = BigInt(readBytes), writeTotal = BigInt(writeBytes);
    const totals = [readTotal, writeTotal, readTotal + writeTotal];
    this.rows.forEach((row, index) => {
      row.cells[1].textContent = formatTransferSize(current[index]) + '/s';
      row.cells[2].textContent = transferBytes.format(totals[index]);
      row.cells[2].title = formatTransferSize(Number(totals[index]));
    });

    const scale = peak > 0 ? 2 ** Math.ceil(Math.log2(peak)) : 1024;
    this.ceiling.textContent = formatTransferSize(scale) + '/s';
    const paths = [[], [], []];
    for (const [i, sample] of samples.entries()) {
      const x = 10 * (60 - samples.length + i);
      const point = value => x + ',' + (99 - 98 * value / scale).toFixed(2);
      paths[0].push(point(sample.readBytes));
      paths[1].push(point(sample.writeBytes));
      paths[2].push(point(sample.readBytes + sample.writeBytes));
    }
    this.lines.forEach((line, i) => line.setAttribute('points', paths[i].join(' ')));
    this.area.setAttribute('points', paths[2].length ? paths[2].join(' ') + ' 590,100 ' + (60 - samples.length) * 10 + ',100' : '');
  }
}

// Each visible view owns one poller and disposes it when it leaves the screen.
function watchTransfers(load, apply, onError) {
  let stopped = false, timer = 0, request = null;
  async function poll() {
    if (stopped || document.hidden || request) return;
    request = new AbortController();
    const started = performance.now();
    let delay = 1000;
    try {
      const snapshot = await load(request.signal);
      if (!request.signal.aborted) apply(snapshot);
    } catch (error) {
      if (!request.signal.aborted) { delay = 3000; onError(error); }
    } finally {
      const aborted = request.signal.aborted;
      request = null;
      if (!stopped && !document.hidden)
        timer = setTimeout(poll, aborted ? 0 : Math.max(100, delay - (performance.now() - started)));
    }
  }
  function visibilityChanged() {
    clearTimeout(timer);
    if (document.hidden) request?.abort();
    else void poll();
  }
  document.addEventListener('visibilitychange', visibilityChanged);
  void poll();
  return () => {
    stopped = true;
    clearTimeout(timer);
    request?.abort();
    document.removeEventListener('visibilitychange', visibilityChanged);
  };
}
