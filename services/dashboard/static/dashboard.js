const refreshSeconds = Number(document.body.dataset.refreshSeconds || "3");

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function badgeList(items, className = "") {
  if (!items || items.length === 0) {
    return '<span class="subtle">none</span>';
  }
  return items.map(item => `<span class="badge ${className}">${escapeHtml(item)}</span>`).join("");
}

function renderGatewayAssets(exposed, failed) {
  const exposedItems = exposed || [];
  const failedItems = failed || [];
  if (exposedItems.length === 0 && failedItems.length === 0) {
    return '<span class="subtle">none</span>';
  }
  return [
    exposedItems.map(item => `<span class="badge">${escapeHtml(item)}</span>`).join(""),
    failedItems.map(item => `<span class="badge bad">${escapeHtml(item)}</span>`).join(""),
  ].filter(Boolean).join(" ");
}

function renderMetrics(data) {
  const metrics = [
    ["Attackers", data.metrics.attacker_count, "Distinct attacker keys with profile or observation data"],
    ["Active Bindings", data.metrics.active_bindings, "Bindings currently marked active"],
    ["Running Assets", data.metrics.running_assets, "Docker-backed adaptive assets still up"],
    ["Failed Assets", data.metrics.failed_assets, "Assets recorded as failed for any binding"],
    ["Public HTTP Events", data.metrics.entrypoint_event_count, "Captured public portal breadcrumbs and direct HTTP probes"],
    ["Cowrie Events", data.metrics.cowrie_event_count, "Sanitized SSH telemetry events"],
    ["OpenCanary Events", data.metrics.opencanary_event_count, "Sanitized multi-protocol telemetry events"],
    ["Containers Up", data.metrics.containers_up, "Compose services or runtime assets currently up"],
    ["Published Ports", data.metrics.published_port_count, "Host-reachable ports in current container view"],
    ["Healthy Stages", data.metrics.healthy_chain_stages, "Pipeline health stages currently green"],
    ["Warnings", data.metrics.warning_chain_stages, "Pipeline stages waiting for data or reporting failure"],
  ];
  document.getElementById("metrics").innerHTML = metrics.map(([label, value, hint]) => `
    <div class="metric">
      <div class="label">${escapeHtml(label)}</div>
      <div class="value">${escapeHtml(value)}</div>
      <div class="hint">${escapeHtml(hint)}</div>
    </div>
  `).join("");
}

function statusBadge(status) {
  const label = status || "unknown";
  const className = label === "ok" ? "good" : label === "bad" ? "bad" : "warn";
  return `<span class="status-badge ${className}">${escapeHtml(label)}</span>`;
}

function renderHealth(stages) {
  if (!stages.length) {
    return '<div class="empty">No pipeline health data.</div>';
  }
  return `<table>
    <thead>
      <tr><th>Stage</th><th>Status</th><th>Component</th><th>Signal</th><th>Detail</th></tr>
    </thead>
    <tbody>
      ${stages.map(stage => `
        <tr>
          <td>${escapeHtml(stage.stage)}</td>
          <td>${statusBadge(stage.status)}</td>
          <td class="mono">${escapeHtml(stage.component || "-")}</td>
          <td class="mono">${escapeHtml(stage.signal || "-")}</td>
          <td>${escapeHtml(stage.detail || "-")}</td>
        </tr>
      `).join("")}
    </tbody>
  </table>`;
}

function renderContainerTable(containers) {
  if (!containers.length) {
    return '<div class="empty">No containers found.</div>';
  }
  return `<table>
    <thead>
      <tr><th>Name</th><th>Kind</th><th>Status</th><th>Ports</th></tr>
    </thead>
    <tbody>
      ${containers.map(container => `
        <tr>
          <td class="mono">${escapeHtml(container.name)}</td>
          <td>${escapeHtml(container.kind)}</td>
          <td>${escapeHtml(container.status)}</td>
          <td class="mono">${escapeHtml(container.ports || "-")}</td>
        </tr>
      `).join("")}
    </tbody>
  </table>`;
}

function renderBindings(bindings, routes) {
  if (!bindings.length) {
    return '<div class="empty">No bindings yet.</div>';
  }
  const routesByBinding = Object.fromEntries(routes.map(route => [route.binding_id, route]));
  return `<table>
    <thead>
      <tr><th>Binding</th><th>Attacker</th><th>Status</th><th>Unlocked</th><th>Gateway</th></tr>
    </thead>
    <tbody>
      ${bindings.map(binding => {
        const route = routesByBinding[binding.binding_id] || {};
        const exposed = route.exposed_assets || [];
        const failed = route.failed_assets || [];
        return `
          <tr>
            <td class="mono">${escapeHtml(binding.binding_id)}</td>
            <td class="mono">${escapeHtml(binding.attacker_key)}</td>
            <td>${escapeHtml(binding.status || "unknown")}</td>
            <td>${badgeList(binding.unlocked_assets || [])}</td>
            <td>${renderGatewayAssets(exposed, failed)}</td>
          </tr>
        `;
      }).join("")}
    </tbody>
  </table>`;
}

function renderAttackers(attackers) {
  if (!attackers.length) {
    return '<div class="empty">No attacker profile data yet.</div>';
  }
  return `<div class="attacker-list">
    ${attackers.map(attacker => `
      <article class="attacker-card">
        <div class="attacker-head">
          <div>
            <h3 class="mono">${escapeHtml(attacker.attacker_key)}</h3>
            <div class="attacker-meta">binding ${escapeHtml(attacker.binding_id || "-")}</div>
          </div>
          <div>${badgeList((attacker.current_running_assets || []).map(asset => asset.asset_id || asset.asset_name || "asset"))}</div>
        </div>
        <div class="kv"><div class="key">Tactics</div><div>${badgeList(attacker.recent_tactics || [])}</div></div>
        <div class="kv"><div class="key">Techniques</div><div>${badgeList(attacker.recent_techniques || [], "warn")}</div></div>
        <div class="kv"><div class="key">Commands</div><div>${badgeList(attacker.commands || [])}</div></div>
        <div class="kv"><div class="key">Unlocked</div><div>${badgeList(attacker.unlocked_assets || [])}</div></div>
        <div class="kv"><div class="key">Running</div><div>${badgeList((attacker.current_running_assets || []).map(asset => `${asset.asset_id} ${asset.ports.join(", ")}`))}</div></div>
        <div class="kv"><div class="key">Failed</div><div>${badgeList((attacker.failed_assets || []).map(asset => `${asset.asset_id} ${asset.failure_detail || asset.current_container_status || "failed"}`), "bad")}</div></div>
      </article>
    `).join("")}
  </div>`;
}

function renderObservationTable(records, columns) {
  if (!records.length) {
    return '<div class="empty">No events yet.</div>';
  }
  return `<table>
    <thead>
      <tr>${columns.map(column => `<th>${escapeHtml(column.label)}</th>`).join("")}</tr>
    </thead>
    <tbody>
      ${records.map(record => `
        <tr>
          ${columns.map(column => `<td class="${column.mono ? "mono" : ""}">${escapeHtml(column.value(record))}</td>`).join("")}
        </tr>
      `).join("")}
    </tbody>
  </table>`;
}

async function loadData() {
  const response = await fetch("/api/summary", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`dashboard summary failed with ${response.status}`);
  }
  const data = await response.json();
  renderMetrics(data);
  const healthPanel = document.getElementById("health-panel");
  if (healthPanel) {
    healthPanel.innerHTML = renderHealth(data.chain_health || []);
  }
  document.getElementById("containers-panel").innerHTML = renderContainerTable(data.containers || []);
  document.getElementById("bindings-panel").innerHTML = renderBindings(data.bindings || [], data.gateway_routes || []);
  document.getElementById("attackers-panel").innerHTML = renderAttackers(data.attackers || []);
  document.getElementById("entrypoint-panel").innerHTML = renderObservationTable(
    data.recent_entrypoint_observations || [],
    [
      { label: "Time", value: row => row.ts || row.timestamp || "-", mono: true },
      { label: "Attacker", value: row => row.attacker_key || "-", mono: true },
      { label: "Method", value: row => row.method || "-" },
      { label: "Path", value: row => row.path || "-", mono: true },
      { label: "Status", value: row => row.response_status ?? "-" },
    ],
  );
  document.getElementById("cowrie-panel").innerHTML = renderObservationTable(
    data.recent_cowrie_observations || [],
    [
      { label: "Time", value: row => row.ts || row.timestamp || "-", mono: true },
      { label: "Attacker", value: row => row.attacker_key || row.src_ip || "-", mono: true },
      { label: "Event", value: row => row.eventid || "-", mono: true },
      { label: "Command", value: row => row.command || "-" },
      { label: "Session", value: row => row.session || "-", mono: true },
    ],
  );
  document.getElementById("opencanary-panel").innerHTML = renderObservationTable(
    data.recent_opencanary_observations || [],
    [
      { label: "Time", value: row => row.ts || row.utc_time || "-", mono: true },
      { label: "Attacker", value: row => row.attacker_key || row.src_host || "-", mono: true },
      { label: "Service", value: row => row.service || "-", mono: true },
      { label: "Port", value: row => row.dst_port ?? "-" },
      { label: "User", value: row => row.username || "-" },
      { label: "Password", value: row => row.password_seen ? "seen" : "-" },
    ],
  );
  document.getElementById("refresh-label").textContent = `Updated ${new Date(data.generated_at).toLocaleTimeString()} | every ${refreshSeconds}s`;
}

async function tick() {
  try {
    await loadData();
  } catch (error) {
    document.getElementById("refresh-label").textContent = `Dashboard refresh failed: ${error.message}`;
  }
}

tick();
setInterval(tick, refreshSeconds * 1000);
