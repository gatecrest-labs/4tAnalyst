// admin.js — dashboard, graph, and admin tab logic

// ---- Dashboard ----
(function () {
  if (!document.getElementById('cpu-chart')) return;
  const COLORS = ['#e74c3c', '#3498db', '#2ecc71'];
  const KEYS = ['cpu_pct', 'mem_pct', 'disk_pct'];
  const LABELS = ['CPU %', 'Memory %', 'Disk %'];
  const IDS = ['cpu-chart', 'mem-chart', 'disk-chart'];
  const CARDS = ['cpu-val', 'mem-val', 'disk-val'];
  const charts = IDS.map((id, i) => new Chart(document.getElementById(id), {
    type: 'line',
    data: { labels: [], datasets: [{ label: LABELS[i], data: [], borderColor: COLORS[i], fill: false, pointRadius: 0, tension: 0.1 }] },
    options: { responsive: true, maintainAspectRatio: false, animation: false, scales: { y: { min: 0, max: 100 } } }
  }));

  async function load(range) {
    const r = await fetch('/api/admin/metrics?range=' + range);
    if (!r.ok) return;
    const d = await r.json();
    CARDS.forEach((id, i) => { document.getElementById(id).textContent = d.current[KEYS[i]].toFixed(1) + '%'; });
    const labels = d.history.map(row => new Date(row.ts * 1000).toLocaleTimeString());
    charts.forEach((c, i) => {
      c.data.labels = labels;
      c.data.datasets[0].data = d.history.map(row => row[KEYS[i]]);
      c.update('none');
    });
  }

  async function loadUsageSummary() {
    const r = await fetch('/api/admin/usage/summary');
    if (!r.ok) return;
    const d = await r.json();
    document.getElementById('usage-calls-24h').textContent = d.tool_calls_24h.toLocaleString();
    document.getElementById('usage-tokens-24h').textContent = d.total_tokens_24h.toLocaleString();
    document.getElementById('usage-cost-24h').textContent = '$' + d.estimated_cost_24h.toFixed(4);
  }

  let activeRange = '1h';
  load(activeRange);
  loadUsageSummary();
  setInterval(() => load(activeRange), 30000);
  setInterval(loadUsageSummary, 60000);
  document.getElementById('dash-ranges').addEventListener('click', e => {
    const btn = e.target.closest('.range-btn');
    if (!btn) return;
    document.querySelectorAll('#dash-ranges .range-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeRange = btn.dataset.range;
    load(activeRange);
  });
})();

// ---- Graph ----
(function () {
  if (!document.getElementById('usage-chart')) return;
  const PALETTE = ['#1a3a5c', '#2a6099', '#4a90c4', '#7bb3d4', '#a8cee3'];
  const chart = new Chart(document.getElementById('usage-chart'), {
    type: 'line',
    data: { labels: [], datasets: [] },
    options: { responsive: true, animation: false, plugins: { legend: { display: true } } }
  });

  async function load(range, view) {
    const r = await fetch('/api/admin/usage?range=' + range);
    if (!r.ok) return;
    const d = await r.json();
    const labels = d.buckets.map(b => new Date(b.ts * 1000).toLocaleString());
    if (view === 'calls') {
      chart.config.type = 'line';
      chart.data.labels = labels;
      chart.data.datasets = d.by_user.map((u, i) => ({
        label: u.display_label,
        data: d.buckets.map(b => (b.by_user && b.by_user[u.token_label]) ? b.by_user[u.token_label].tool_calls : 0),
        borderColor: PALETTE[i % PALETTE.length],
        backgroundColor: PALETTE[i % PALETTE.length],
        fill: false, tension: 0.2, pointRadius: 3
      }));
      chart.options.scales = {};
    } else if (view === 'tokens') {
      chart.config.type = 'line';
      chart.data.labels = labels;
      chart.data.datasets = [
        { label: 'Input tokens', data: d.buckets.map(b => b.input_tokens || 0), borderColor: '#3498db', backgroundColor: '#3498db', fill: false, tension: 0.2, pointRadius: 3 },
        { label: 'Output tokens', data: d.buckets.map(b => b.output_tokens || 0), borderColor: '#e74c3c', backgroundColor: '#e74c3c', fill: false, tension: 0.2, pointRadius: 3 }
      ];
      chart.options.scales = {};
    } else {
      chart.config.type = 'line';
      chart.data.labels = labels;
      chart.data.datasets = [{ label: 'Cost ($)', data: d.buckets.map(b => b.cost || 0), borderColor: '#2ecc71', fill: false, tension: 0.1 }];
      chart.options.scales = {};
    }
    chart.update();
    document.getElementById('summary-table').innerHTML = '<table><thead><tr><th>User</th><th>Tool Calls</th><th>Input Tokens</th><th>Output Tokens</th><th>Est. Cost</th></tr></thead><tbody>' +
      d.by_user.map(u => `<tr><td>${u.display_label}</td><td>${u.tool_calls}</td><td>${u.input_tokens.toLocaleString()}</td><td>${u.output_tokens.toLocaleString()}</td><td>$${u.estimated_cost.toFixed(4)}</td></tr>`).join('') +
      '</tbody></table>';
  }

  let activeRange = '86400', activeView = 'calls';
  load(activeRange, activeView);
  document.getElementById('graph-ranges').addEventListener('click', e => {
    const btn = e.target.closest('.range-btn');
    if (!btn) return;
    document.querySelectorAll('#graph-ranges .range-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeRange = btn.dataset.range;
    load(activeRange, activeView);
  });
  document.querySelector('.view-selector').addEventListener('click', e => {
    const btn = e.target.closest('.view-btn');
    if (!btn) return;
    document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeView = btn.dataset.view;
    load(activeRange, activeView);
  });
  document.getElementById('custom-apply').addEventListener('click', () => {
    const s = document.getElementById('custom-start').value;
    const en = document.getElementById('custom-end').value;
    if (s && en) { activeRange = String(Math.max(60, Math.floor((new Date(en) - new Date(s)) / 1000))); load(activeRange, activeView); }
  });
})();

// ---- Admin tab ----
(function () {
  if (!document.getElementById('users-tbody')) return;

  async function loadAll() {
    const [ur, tr] = await Promise.all([fetch('/api/admin/users'), fetch('/api/admin/tokens')]);
    const users = await ur.json();
    const tokens = await tr.json();
    document.getElementById('users-tbody').innerHTML = users.map(u =>
      `<tr><td>${u.username}</td><td>${u.role}</td><td>${u.created_at}</td><td>
        <button class="action" onclick="adminResetPw('${u.username}')">Reset PW</button>
        <button class="action" onclick="adminChangeRole('${u.username}','${u.role}')">Toggle Role</button>
        <button class="action danger" onclick="adminDeleteUser('${u.username}')">Delete</button>
      </td></tr>`).join('');
    document.getElementById('tokens-tbody').innerHTML = tokens.map((t, i) =>
      `<tr><td>${t.label}</td><td>...${t.token_suffix}</td>
        <td contenteditable="true" data-idx="${i}" class="adom-cell">${t.adoms.join(', ')}</td>
        <td>
          <button class="action" onclick="adminSaveAdoms(${i})">Save</button>
          <button class="action danger" onclick="adminDeleteToken(${i})">Delete</button>
        </td></tr>`).join('');
  }

  window.adminDeleteUser = async (u) => { if (!confirm(`Delete ${u}?`)) return; await fetch('/api/admin/users/' + u, { method: 'DELETE' }); loadAll(); };
  window.adminChangeRole = async (u, r) => { const nr = r === 'admin' ? 'viewer' : 'admin'; if (!confirm(`Change ${u} to ${nr}?`)) return; await fetch('/api/admin/users/' + u + '/role', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ role: nr }) }); loadAll(); };
  window.adminResetPw = async (u) => { const pw = prompt('New password:'); if (!pw) return; await fetch('/api/admin/users/' + u + '/password', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }) }); };
  window.adminSaveAdoms = async (i) => { const cell = document.querySelector(`.adom-cell[data-idx="${i}"]`); const adoms = cell.textContent.split(',').map(s => s.trim()).filter(Boolean); await fetch('/api/admin/tokens/' + i + '/adoms', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ adoms }) }); alert('Saved.'); };
  window.adminDeleteToken = async (i) => { if (!confirm('Delete token?')) return; await fetch('/api/admin/tokens/' + i, { method: 'DELETE' }); loadAll(); };

  document.getElementById('add-user-btn').addEventListener('click', async () => {
    const username = prompt('Username:'); if (!username) return;
    const role = prompt('Role (admin/viewer):', 'viewer'); if (!role) return;
    const password = prompt('Password:'); if (!password) return;
    const r = await fetch('/api/admin/users', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, role, password }) });
    if (!r.ok) { const e = await r.json(); alert(e.detail); return; }
    loadAll();
  });

  loadAll();
})();
