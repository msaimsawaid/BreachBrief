(() => {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('file-input');
  const btnBrowse = document.getElementById('btn-browse');
  const btnAnalyze = document.getElementById('btn-analyze');
  const btnSample = document.getElementById('btn-sample');
  const dzFilelist = document.getElementById('dz-filelist');
  const landError = document.getElementById('land-error');
  const landLoading = document.getElementById('land-loading');
  const loadingMsg = document.getElementById('loading-msg');
  const loadingPct = document.getElementById('loading-pct');
  const progressFill = document.getElementById('progress-fill');
  const land = document.getElementById('land');
  const dash = document.getElementById('dash');
  const btnNew = document.getElementById('btn-new');
  const tbStatus = document.getElementById('tb-status');
  const chkHideNoise = document.getElementById('chk-hide-noise');
  const reportModeSelect = document.getElementById('report-mode-select');

  let selectedFiles = [];
  let currentAnalysisId = null;
  let currentData = null;
  let pollTimer = null;

  const PAGE_SIZE = 50;
  let overviewPage = 0;
  let findingsPage = 0;

  const DISPOSITIONS = ['malicious', 'likely_malicious', 'suspicious', 'benign', 'likely_benign', 'informational', 'unknown'];
  const DISP_LABELS = {
    malicious: 'Malicious', likely_malicious: 'Likely Malicious', suspicious: 'Suspicious',
    benign: 'Benign', likely_benign: 'Likely Benign', informational: 'Informational', unknown: 'Unknown',
  };

  // ---- resilient fetch helper: never throws on non-JSON responses ----
  async function safeFetchJson(url, options) {
    const res = await fetch(url, options);
    const text = await res.text();
    let body;
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      throw new Error(`Server returned an unexpected response (${res.status}). Try again or check the server logs.`);
    }
    if (!res.ok) throw new Error(body.error || `Request failed (${res.status}).`);
    return body;
  }

  // ---- dropzone interactions ----
  btnBrowse.addEventListener('click', (e) => { e.stopPropagation(); fileInput.click(); });
  dropzone.addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', () => addFiles(fileInput.files));

  ['dragenter', 'dragover'].forEach(evt =>
    dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.add('drag-over'); }));
  ['dragleave', 'drop'].forEach(evt =>
    dropzone.addEventListener(evt, (e) => { e.preventDefault(); dropzone.classList.remove('drag-over'); }));
  dropzone.addEventListener('drop', (e) => addFiles(e.dataTransfer.files));

  function addFiles(fileList) {
    const valid = /\.(json|log|txt)$/i;
    for (const f of fileList) {
      if (valid.test(f.name)) selectedFiles.push(f);
    }
    renderFileChips();
  }

  function renderFileChips() {
    dzFilelist.innerHTML = '';
    selectedFiles.forEach((f, idx) => {
      const chip = document.createElement('div');
      chip.className = 'dz-chip';
      chip.textContent = `${f.name} ✕`;
      chip.title = 'Click to remove';
      chip.addEventListener('click', (e) => {
        e.stopPropagation();
        selectedFiles.splice(idx, 1);
        renderFileChips();
      });
      dzFilelist.appendChild(chip);
    });
    btnAnalyze.disabled = selectedFiles.length === 0;
  }

  function showError(msg) {
    landError.textContent = msg;
    landError.classList.add('show');
    dropzone.classList.add('err-shake');
    setTimeout(() => dropzone.classList.remove('err-shake'), 450);
    setTimeout(() => landError.classList.remove('show'), 6000);
  }

  function setProgress(pct, message) {
    progressFill.style.width = `${pct}%`;
    loadingPct.textContent = `${pct}%`;
    if (message) loadingMsg.textContent = message;
  }

  // ---- run analysis (background job + polling) — no window param; the
  // engine uses a fixed sensible default now that there's a real progress
  // loader instead of asking the person to guess a correlation window
  // before they've even seen their data. ----
  btnAnalyze.addEventListener('click', () => {
    if (!selectedFiles.length) return;
    const fd = new FormData();
    selectedFiles.forEach(f => fd.append('files', f));
    startJob(fd);
  });

  btnSample.addEventListener('click', () => {
    landLoading.classList.add('show');
    setProgress(10, 'Running sample incident…');
    safeFetchJson('/api/sample', { method: 'POST' })
      .then((data) => {
        landLoading.classList.remove('show');
        showDashboard(data);
      })
      .catch((err) => {
        landLoading.classList.remove('show');
        showError(err.message);
      });
  });

  function startJob(fd) {
    landLoading.classList.add('show');
    setProgress(0, 'Uploading files…');
    safeFetchJson('/api/analyze', { method: 'POST', body: fd })
      .then((data) => pollJob(data.job_id))
      .catch((err) => {
        landLoading.classList.remove('show');
        showError(err.message);
      });
  }

  function pollJob(jobId) {
    clearInterval(pollTimer);
    pollTimer = setInterval(() => {
      safeFetchJson(`/api/analyze/${jobId}/status`)
        .then((status) => {
          setProgress(status.pct || 0, status.message);
          if (status.status === 'done') {
            clearInterval(pollTimer);
            return safeFetchJson(`/api/analyze/${jobId}/result`).then((data) => {
              landLoading.classList.remove('show');
              showDashboard(data);
            });
          }
          if (status.status === 'error') {
            clearInterval(pollTimer);
            landLoading.classList.remove('show');
            showError(status.error || 'Analysis failed.');
          }
        })
        .catch((err) => {
          clearInterval(pollTimer);
          landLoading.classList.remove('show');
          showError(err.message);
        });
    }, 1200);
  }

  function showDashboard(data) {
    overviewPage = 0;
    findingsPage = 0;
    renderDashboard(data);
    land.classList.add('hide');
    dash.classList.add('show');
  }

  btnNew.addEventListener('click', () => {
    clearInterval(pollTimer);
    dash.classList.remove('show');
    land.classList.remove('hide');
    selectedFiles = [];
    renderFileChips();
  });

  // ---- rendering helpers ----
  function badge(level) {
    const cls = (level || 'low').toLowerCase();
    return `<span class="badge ${cls}">${level}</span>`;
  }

  function confidenceBar(pct) {
    const cls = pct >= 75 ? 'high' : pct >= 50 ? 'mid' : 'low';
    return `<span class="conf-bar"><span class="conf-track"><span class="conf-fill ${cls}" style="width:${pct}%"></span></span><span class="conf-pct">${pct.toFixed(0)}%</span></span>`;
  }

  function priorityBadge(pri) {
    return `<span class="pri-badge ${pri}">${pri}</span>`;
  }

  function dispositionSelect(g) {
    const current = g.user_disposition || g.auto_disposition;
    const isOverride = !!g.user_disposition;
    const opts = DISPOSITIONS.map(d =>
      `<option value="${d}" ${d === current ? 'selected' : ''}>${DISP_LABELS[d]}${!isOverride && d === g.auto_disposition ? ' (suggested)' : ''}</option>`
    ).join('');
    return `<select class="disp-select ${isOverride ? 'override' : 'auto'}" data-gid="${g.group_id}">${opts}</select>`;
  }

  function wireDispositionSelects(container) {
    container.querySelectorAll('.disp-select').forEach(sel => {
      sel.addEventListener('change', () => setDisposition(sel.dataset.gid, sel.value));
      sel.addEventListener('click', (e) => e.stopPropagation());
    });
  }

  function setDisposition(groupId, disposition, notes) {
    if (!currentAnalysisId) return;
    const body = { group_ids: [groupId], disposition };
    if (notes !== undefined) body.notes = notes;
    safeFetchJson(`/api/analysis/${currentAnalysisId}/disposition`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then(() => {
      const applyTo = (list) => list.forEach(g => {
        if (g.group_id === groupId) {
          g.user_disposition = disposition;
          if (notes !== undefined) g.user_notes = notes;
        }
      });
      applyTo(currentData.aggregated_events);
      applyTo(currentData.timeline);
      renderDashboard(currentData, true);
    }).catch(err => showError(err.message));
  }

  function mapChips(m) {
    const chips = [];
    if (m.MITRE) {
      const conf = m.mitre_confidence ? ` ${m.mitre_confidence}%` : '';
      chips.push(`MITRE ${m.MITRE}${conf}`);
    }
    if (m.CWE) chips.push(m.CWE);
    if (m.OWASP) chips.push(m.OWASP);
    if (m.NIST) chips.push(m.NIST);
    if (m.CIS) chips.push(m.CIS);
    if (m.CVE && m.CVE.length) chips.push(...m.CVE);
    return chips.map(c => `<span class="map-chip">${escapeHtml(c)}</span>`).join('');
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  function ipDisplay(g) {
    const ips = (g.source_ips && g.source_ips.length) ? g.source_ips : (g.source_ip && g.source_ip !== 'unknown' ? [g.source_ip] : []);
    if (!ips.length) return '-';
    if (ips.length === 1) return escapeHtml(ips[0]);
    return `${escapeHtml(ips[0])} <span style="color:var(--dim)">(+${ips.length - 1} more)</span>`;
  }

  function visibleGroups(groups) {
    if (!chkHideNoise.checked) return groups;
    return groups.filter(g => !(g.possible_false_positive && !g.user_disposition));
  }

  function paginate(items, page) {
    const start = page * PAGE_SIZE;
    return { slice: items.slice(start, start + PAGE_SIZE), start };
  }

  function renderPager(el, total, page, onChange) {
    const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    el.innerHTML = '';
    if (totalPages <= 1) return;
    const prev = document.createElement('button');
    prev.textContent = '← Prev';
    prev.disabled = page === 0;
    prev.addEventListener('click', () => onChange(page - 1));
    const info = document.createElement('span');
    info.className = 'pg-info';
    info.textContent = `Page ${page + 1} of ${totalPages} · ${total} rows`;
    const next = document.createElement('button');
    next.textContent = 'Next →';
    next.disabled = page >= totalPages - 1;
    next.addEventListener('click', () => onChange(page + 1));
    el.appendChild(prev);
    el.appendChild(info);
    el.appendChild(next);
  }

  function reasoningHtml(g) {
    const r = g.reasoning;
    if (!r) return '';
    const listBlock = (label, items, cls) => items && items.length
      ? `<div class="reason-block ${cls}"><b>${label}:</b> ${items.map(escapeHtml).join(' ')}</div>` : '';
    const basis = (r.confidence_breakdown || [])
      .map(c => `${escapeHtml(c.label)} (${c.points} pts)`).join(' + ');
    return `
      <div class="reasoning-panel">
        <div class="reason-why"><b>Why this was flagged:</b> ${escapeHtml(r.reasoning_text)}</div>
        ${basis ? `<div class="reason-basis">Confidence basis: ${basis} = ${g.confidence.toFixed(0)}%</div>` : ''}
        ${listBlock('Observed', r.observed, 'observed')}
        ${listBlock('Derived', r.derived, 'derived')}
        ${listBlock('Inferred', r.inferred, 'inferred')}
        ${listBlock('Not observed', r.not_observed, 'not-observed')}
      </div>`;
  }

  function evidenceHtml(g) {
    if (!g.evidence || !g.evidence.length) return '';
    const rows = g.evidence.map(ev => `
      <div class="evidence-row">
        <b>${escapeHtml(ev.timestamp || '?')}</b> · ${escapeHtml(ev.source_ip || '-')} · ${escapeHtml(ev.agent || '-')}
        · ${escapeHtml(ev.rule_id || '')} ${escapeHtml(ev.rule_description || '')}<br>
        ${escapeHtml(ev.raw_message || '')}
      </div>`).join('');
    return `
      <span class="evidence-toggle" data-gid="${g.group_id}">Show reasoning &amp; evidence (${g.evidence.length} sample events) ▾</span>
      <div class="evidence-panel" id="ev-${g.group_id}">${reasoningHtml(g)}${rows}</div>`;
  }

  function wireEvidenceToggles(container) {
    container.querySelectorAll('.evidence-toggle').forEach(t => {
      t.addEventListener('click', () => {
        const panel = document.getElementById(`ev-${t.dataset.gid}`);
        if (panel) panel.classList.toggle('show');
      });
    });
  }

  chkHideNoise.addEventListener('change', () => {
    if (currentData) renderDashboard(currentData, true);
  });

  // ---- main render ----
  function renderDashboard(data, preservePage) {
    currentAnalysisId = data.analysis_id;
    currentData = data;
    if (!preservePage) { overviewPage = 0; findingsPage = 0; }

    tbStatus.textContent = `analysis ${data.analysis_id} · ${data.generated_at}`;
    document.getElementById('s-files').textContent = data.stats.total_files;
    document.getElementById('s-raw').textContent = data.stats.total_raw_events;
    document.getElementById('s-agg').textContent = data.stats.total_aggregated_events;
    document.getElementById('s-ips').textContent = data.stats.unique_source_ips;
    document.getElementById('s-posture').textContent = data.stats.overall_posture;
    document.getElementById('s-fp').textContent = data.stats.possible_false_positive_count || 0;

    const allGroups = [...data.aggregated_events].sort((a, b) => b.risk_score - a.risk_score);
    const shown = visibleGroups(allGroups);

    // Overview table
    const tbody = document.querySelector('#overview-table tbody');
    tbody.innerHTML = '';
    if (!shown.length) {
      tbody.innerHTML = `<tr><td colspan="9" class="empty-note">Nothing to show — try unchecking "Hide likely noise".</td></tr>`;
    }
    const { slice: ovSlice } = paginate(shown, overviewPage);
    ovSlice.forEach(g => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td style="font-family:Inter;font-weight:600">${escapeHtml(g.event_type)}${g.possible_false_positive ? ' <span class="badge noise">noise?</span>' : ''}</td>
        <td>${g.count}</td>
        <td>${g.start_time} – ${g.end_time}</td>
        <td>${ipDisplay(g)}</td>
        <td>${badge(g.severity)}</td>
        <td>${confidenceBar(g.confidence)}</td>
        <td>${priorityBadge(g.priority)}</td>
        <td>${dispositionSelect(g)}</td>
        <td>${badge(g.risk_level)} <span style="color:var(--dim)">${g.risk_score}</span></td>`;
      tbody.appendChild(tr);
    });
    wireDispositionSelects(tbody);
    renderPager(document.getElementById('overview-pager'), shown.length, overviewPage, (p) => { overviewPage = p; renderDashboard(data, true); });

    // Timeline
    document.getElementById('timeline-summary').textContent = data.timeline_summary;
    const tlList = document.getElementById('timeline-list');
    tlList.innerHTML = '';
    if (!data.timeline.length) {
      tlList.innerHTML = `<div class="empty-note">Nothing to chart yet.</div>`;
    }
    data.timeline.slice(0, 300).forEach(t => {
      const row = document.createElement('div');
      row.className = 'tl-row';
      row.innerHTML = `
        <div class="tl-time">${t.time_label}</div>
        <div>
          <div class="tl-stage">${escapeHtml(t.stage)}</div>
          <div class="tl-narrative">${escapeHtml(t.narrative)}</div>
        </div>`;
      tlList.appendChild(row);
    });

    // Findings (paginated, full detail: confidence/priority/disposition/notes/evidence)
    const findingsList = document.getElementById('findings-list');
    findingsList.innerHTML = '';
    if (!shown.length) {
      findingsList.innerHTML = `<div class="card"><div class="empty-note">Nothing to detail — try unchecking "Hide likely noise".</div></div>`;
    }
    const { slice: fSlice } = paginate(shown, findingsPage);
    fSlice.forEach(g => {
      const card = document.createElement('div');
      card.className = 'finding-card';
      card.innerHTML = `
        <div class="finding-head">
          <div class="finding-title">${escapeHtml(g.event_type)}${g.possible_false_positive ? ' <span class="badge noise">noise?</span>' : ''} — ${ipDisplay(g)}</div>
          ${badge(g.risk_level)}
        </div>
        <div class="finding-meta">
          Occurred <b>${g.count}</b> time(s) between ${g.start_time} and ${g.end_time} ·
          severity ${g.severity} · destination(s): ${escapeHtml(g.destination_ips.join(', ') || 'n/a')} ·
          port(s): ${escapeHtml(g.ports.join(', ') || 'n/a')}
          ${g.agents_seen && g.agents_seen.length > 1 ? ` · ${g.agents_seen.length} hosts` : ''}
        </div>
        <div style="display:flex;align-items:center;gap:14px;margin:8px 0;flex-wrap:wrap">
          <span style="font-size:10px;color:var(--dim)">Confidence ${confidenceBar(g.confidence)}</span>
          ${priorityBadge(g.priority)}
          ${dispositionSelect(g)}
        </div>
        <div class="finding-map">${mapChips(g.mapping)}</div>
        <textarea class="notes-field" placeholder="Analyst notes…" data-gid="${g.group_id}">${escapeHtml(g.user_notes || '')}</textarea>
        ${evidenceHtml(g)}`;
      findingsList.appendChild(card);
    });
    wireDispositionSelects(findingsList);
    wireEvidenceToggles(findingsList);
    findingsList.querySelectorAll('.notes-field').forEach(ta => {
      ta.addEventListener('blur', () => {
        const gid = ta.dataset.gid;
        const g = currentData.aggregated_events.find(x => x.group_id === gid);
        const disp = (g && (g.user_disposition || g.auto_disposition)) || 'unknown';
        setDisposition(gid, disp, ta.value);
      });
    });
    renderPager(document.getElementById('findings-pager'), shown.length, findingsPage, (p) => { findingsPage = p; renderDashboard(data, true); });

    // Risk
    const riskList = document.getElementById('risk-list');
    riskList.innerHTML = '';
    if (!data.top_threats.length) {
      riskList.innerHTML = `<div class="empty-note">No threats to rank.</div>`;
    }
    data.top_threats.forEach((g, idx) => {
      const row = document.createElement('div');
      row.className = 'risk-row';
      row.innerHTML = `
        <div class="risk-rank">${idx + 1}</div>
        <div class="risk-info">
          <div style="font-weight:700;font-size:13px">${escapeHtml(g.event_type)}</div>
          <div style="font-size:11px;color:var(--dim)">${escapeHtml(g.source_ip || 'unknown')} · ${g.count} occurrence(s) · ${g.confidence != null ? g.confidence.toFixed(0) + '% confidence' : ''}</div>
        </div>
        ${g.priority ? priorityBadge(g.priority) : ''}
        ${badge(g.risk_level)}
        <div class="risk-score">${g.risk_score}</div>`;
      riskList.appendChild(row);
    });

    // Recommendations
    const recsList = document.getElementById('recs-list');
    recsList.innerHTML = '';
    if (!data.recommendations.length) {
      recsList.innerHTML = `<div class="empty-note">No specific recommendations generated.</div>`;
    }
    data.recommendations.forEach(r => {
      const row = document.createElement('div');
      row.className = 'rec-row';
      row.innerHTML = `
        <div class="dot"></div>
        <div>
          <div class="rec-title">${escapeHtml(r.event_type)}</div>
          <div class="rec-action">${escapeHtml(r.action)}</div>
        </div>`;
      recsList.appendChild(row);
    });
  }

  // ---- view tabs ----
  document.querySelectorAll('.vtab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.vtab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`view-${tab.dataset.view}`).classList.add('active');
    });
  });

  // ---- report downloads (mode-aware) ----
  document.getElementById('btn-dl-docx').addEventListener('click', () => {
    if (currentAnalysisId) window.location.href = `/api/report/docx/${currentAnalysisId}?mode=${reportModeSelect.value}`;
  });
  document.getElementById('btn-dl-pdf').addEventListener('click', () => {
    if (currentAnalysisId) window.location.href = `/api/report/pdf/${currentAnalysisId}?mode=${reportModeSelect.value}`;
  });

  // ---- back-to-top ----
  const backToTopBtn = document.getElementById('btn-back-to-top');
  if (backToTopBtn) {
    window.addEventListener('scroll', () => {
      backToTopBtn.classList.toggle('show', window.scrollY > 300);
    });
    backToTopBtn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
  }
})();
