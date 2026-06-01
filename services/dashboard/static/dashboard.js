const refreshSeconds = Number(document.body.dataset.refreshSeconds || "3");
const detailOpenState = new Map();
let rendering = false;

document.addEventListener("click", event => {
  const summary = event.target.closest("summary");
  if (!summary) {
    return;
  }
  const detail = summary.parentElement;
  if (!(detail instanceof HTMLDetailsElement)) {
    return;
  }
  const key = detail.dataset.detailKey;
  if (key) {
    detailOpenState.set(key, !detail.open);
  }
}, true);

document.addEventListener("toggle", event => {
  if (rendering) {
    return;
  }
  const detail = event.target;
  if (!(detail instanceof HTMLDetailsElement)) {
    return;
  }
  const key = detail.dataset.detailKey;
  if (key) {
    detailOpenState.set(key, detail.open);
  }
}, true);

function syncDetailOpenState(root = document) {
  root.querySelectorAll("details[data-detail-key]").forEach(detail => {
    detailOpenState.set(detail.dataset.detailKey, detail.open);
  });
}

function replacePanelHtml(elementId, html) {
  syncDetailOpenState();
  const element = document.getElementById(elementId);
  rendering = true;
  element.innerHTML = html;
  rendering = false;
}

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

function techniqueBadgeList(techniques, confidences = {}) {
  const labels = (techniques || []).map(technique => {
    const confidence = Number(confidences[technique]);
    return Number.isFinite(confidence) ? `${technique}:${confidence.toFixed(2)}` : technique;
  });
  return badgeList(labels, "warn");
}

function assetConfigurationLabels(assets) {
  return (assets || []).flatMap(asset => {
    const assetId = asset.asset_id || asset.asset_name || "asset";
    const configurationIds = asset.active_configuration_ids || [];
    return configurationIds.map(configurationId => `${assetId}:${configurationId}`);
  });
}

function runningAssetLabel(asset) {
  const assetId = asset.asset_id || asset.asset_name || "asset";
  const configurationIds = asset.active_configuration_ids || [];
  const target = configurationIds.length ? `${assetId}:${configurationIds.join(",")}` : assetId;
  return `${target} ${asset.ports.join(", ")}`;
}

function detailOpenAttribute(key, defaultOpen = false) {
  const open = detailOpenState.has(key) ? detailOpenState.get(key) : defaultOpen;
  return open ? " open" : "";
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
    ["Asset Routes", data.metrics.asset_gateway_route_count, "Data-plane routes served by the unified asset gateway"],
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

function renderAssetGatewayRoutes(routes) {
  if (!routes || routes.length === 0) {
    return '<span class="subtle">none</span>';
  }
  return routes.map(route => {
    const publicPort = route.public_port || "?";
    const backend = `${route.backend_host || "?"}:${route.backend_port || "?"}`;
    return `<span class="badge">${escapeHtml(route.asset_id)} ${escapeHtml(publicPort)} -> ${escapeHtml(backend)}</span>`;
  }).join("");
}

function renderBindings(bindings, routes, assetGatewayRoutes) {
  if (!bindings.length) {
    return '<div class="empty">No bindings yet.</div>';
  }
  const routesByBinding = Object.fromEntries(routes.map(route => [route.binding_id, route]));
  const assetRoutesByBinding = {};
  (assetGatewayRoutes || []).forEach(route => {
    assetRoutesByBinding[route.binding_id] = assetRoutesByBinding[route.binding_id] || [];
    assetRoutesByBinding[route.binding_id].push(route);
  });
  return `<table>
    <thead>
      <tr><th>Binding</th><th>Attacker</th><th>Status</th><th>Unlocked</th><th>Gateway</th><th>Data Plane</th></tr>
    </thead>
    <tbody>
      ${bindings.map(binding => {
        const route = routesByBinding[binding.binding_id] || {};
        const exposed = route.exposed_assets || [];
        const failed = route.failed_assets || [];
        const assetRoutes = assetRoutesByBinding[binding.binding_id] || [];
        return `
          <tr>
            <td class="mono">${escapeHtml(binding.binding_id)}</td>
            <td class="mono">${escapeHtml(binding.attacker_key)}</td>
            <td>${escapeHtml(binding.status || "unknown")}</td>
            <td>${badgeList(binding.unlocked_assets || [])}</td>
            <td>${renderGatewayAssets(exposed, failed)}</td>
            <td>${renderAssetGatewayRoutes(assetRoutes)}</td>
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
    ${attackers.map(attacker => {
      const attackerKey = `attacker:${attacker.attacker_key || "-"}`;
      const runningAssets = (attacker.current_running_assets || []).map(asset => asset.asset_id || asset.asset_name || "asset");
      const latestDecision = (attacker.decisions || []).slice(-1)[0] || {};
      const latestDecisionEvents = latestDecision.decision_events || [];
      const latestDecisionLabel = latestDecisionEvents.length
        ? latestDecisionEvents.map(event => event.asset_id || event.selected_technique || "-").join(", ")
        : (latestDecision.reasons || []).join(", ");
      return `
      <details class="attacker-card" data-detail-key="${escapeHtml(attackerKey)}"${detailOpenAttribute(attackerKey, true)}>
        <summary class="attacker-head">
          <div>
            <h3 class="mono">${escapeHtml(attacker.attacker_key)}</h3>
            <div class="attacker-meta">binding ${escapeHtml(attacker.binding_id || "-")} | ${escapeHtml((attacker.recent_techniques || []).length)} techniques | ${escapeHtml((attacker.decisions || []).length)} decisions</div>
          </div>
          <div class="attacker-preview">
            ${badgeList(runningAssets)}
            ${latestDecisionLabel ? `<span class="badge warn">${escapeHtml(latestDecisionLabel)}</span>` : ""}
          </div>
        </summary>
        <div class="attacker-body">
          <div class="kv"><div class="key">Tactics</div><div>${badgeList(attacker.recent_tactics || [])}</div></div>
          <div class="kv"><div class="key">Techniques</div><div>${techniqueBadgeList(attacker.recent_techniques || [], attacker.confidence_by_technique || {})}</div></div>
          <div class="kv"><div class="key">Commands</div><div>${badgeList(attacker.commands || [])}</div></div>
          <div class="kv"><div class="key">Recent HTTP Evidence</div><div>${badgeList(attacker.public_http_evidence || [])}</div></div>
          <div class="kv"><div class="key">Recent Internal HTTP</div><div>${badgeList(attacker.internal_http_evidence || [])}</div></div>
          <div class="kv"><div class="key">Unlocked</div><div>${badgeList(attacker.unlocked_assets || [])}</div></div>
          <div class="kv"><div class="key">Configured</div><div>${badgeList(assetConfigurationLabels(attacker.current_running_assets || []), "warn")}</div></div>
          <div class="kv"><div class="key">Running</div><div>${badgeList((attacker.current_running_assets || []).map(asset => runningAssetLabel(asset)))}</div></div>
          <div class="kv"><div class="key">Failed</div><div>${badgeList((attacker.failed_assets || []).map(asset => `${asset.asset_id} ${asset.failure_detail || asset.current_container_status || "failed"}`), "bad")}</div></div>
          <div class="kv decision-kv"><div class="key">Decisions</div><div>${renderDecisions(attacker.decisions || [], attacker.attacker_key || "-", attacker.confidence_by_technique || {})}</div></div>
        </div>
      </details>
    `;
    }).join("")}
  </div>`;
}

function renderDecisions(decisions, attackerKey, confidences = {}) {
  if (!decisions.length) {
    return '<span class="subtle">none</span>';
  }
  return `<div class="decision-list">
    ${decisions.slice(-3).reverse().map(decision => renderDecision(decision, attackerKey, confidences)).join("")}
  </div>`;
}

function renderDecision(decision, attackerKey, confidences = {}) {
  const events = decision.decision_events || [];
  const eventRows = events.length
    ? events.map(event => renderDecisionEvent(event)).join("")
    : `<div class="decision-row">${badgeList(decision.reasons || [], "warn")}</div>`;
  const actionLabels = (decision.actions || []).map(action => {
    const target = action.configuration_id
      ? `${action.asset_id}:${action.configuration_id}`
      : action.asset_id;
    return `${action.action_type || "action"} ${target || "-"}`;
  });
  const droppedLabels = (decision.dropped_actions || []).map(action => `${action.action_type || "action"} ${action.asset_id || "-"}`);
  const summary = actionLabels.length ? actionLabels.join(", ") : (decision.reasons || []).join(", ") || "decision";
  const detailKey = `decision:${attackerKey}:${decision.ts || "-"}:${actionLabels.join("|")}`;
  return `<details class="decision-block" data-detail-key="${escapeHtml(detailKey)}"${detailOpenAttribute(detailKey, true)}>
    <summary class="decision-meta">
      <span class="mono">${escapeHtml(decision.ts || "-")}</span>
      <span class="subtle">${escapeHtml(summary)}</span>
      <span>${techniqueBadgeList(decision.recent_techniques || [], confidences)}</span>
    </summary>
    ${eventRows}
    <div class="decision-row subtle">actions ${badgeList(actionLabels)} dropped ${badgeList(droppedLabels, "bad")}</div>
  </details>`;
}

function renderDecisionEvent(event) {
  const support = event.recommendation_support === null || event.recommendation_support === undefined
    ? "-"
    : Number(event.recommendation_support).toFixed(2);
  const confidence = event.confidence_score === null || event.confidence_score === undefined
    ? "-"
    : Number(event.confidence_score).toFixed(2);
  const target = event.configuration_id
    ? `${event.asset_id}:${event.configuration_id}`
    : event.asset_id || "-";
  const labels = [
    event.candidate_type,
    event.selected_technique,
    target,
  ].filter(Boolean);
  const counts = `eligible ${event.eligible_asset_count ?? 0}, rejected ${event.rejected_asset_count ?? 0}, support ${support}, conf ${confidence}`;
  return `<div class="decision-row">
    <div>${badgeList(labels)}</div>
    <div class="subtle">${escapeHtml(counts)}</div>
    <div class="subtle">${badgeList(event.matched_dependency_markers || [])}</div>
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
    replacePanelHtml("health-panel", renderHealth(data.chain_health || []));
  }
  replacePanelHtml("containers-panel", renderContainerTable(data.containers || []));
  replacePanelHtml("bindings-panel", renderBindings(
      data.bindings || [],
      data.gateway_routes || [],
      data.asset_gateway_routes || [],
  ));
  replacePanelHtml("attackers-panel", renderAttackers(data.attackers || []));
  replacePanelHtml("entrypoint-panel", renderObservationTable(
    data.recent_entrypoint_observations || [],
    [
      { label: "Time", value: row => row.ts || row.timestamp || "-", mono: true },
      { label: "Attacker", value: row => row.attacker_key || "-", mono: true },
      { label: "Method", value: row => row.method || "-" },
      { label: "Path", value: row => row.path || "-", mono: true },
      { label: "Rules", value: row => (row.matched_rules || []).join(", ") || "-" },
      { label: "Evidence", value: row => (row.indicators || []).join(", ") || "-" },
      { label: "Status", value: row => row.response_status ?? "-" },
    ],
  ));
  replacePanelHtml("cowrie-panel", renderObservationTable(
    data.recent_cowrie_observations || [],
    [
      { label: "Time", value: row => row.ts || row.timestamp || "-", mono: true },
      { label: "Attacker", value: row => row.attacker_key || row.src_ip || "-", mono: true },
      { label: "Event", value: row => row.eventid || "-", mono: true },
      { label: "Command", value: row => row.command || "-" },
      { label: "Session", value: row => row.session || "-", mono: true },
    ],
  ));
  replacePanelHtml("opencanary-panel", renderObservationTable(
    data.recent_opencanary_observations || [],
    [
      { label: "Time", value: row => row.ts || row.utc_time || "-", mono: true },
      { label: "Attacker", value: row => row.attacker_key || row.src_host || "-", mono: true },
      { label: "Service", value: row => row.service || "-", mono: true },
      { label: "Port", value: row => row.dst_port ?? "-" },
      { label: "User", value: row => row.username || "-" },
      { label: "Password", value: row => row.password_seen ? "seen" : "-" },
    ],
  ));
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
