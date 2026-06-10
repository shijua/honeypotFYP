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

function badgeList(items, className = "", emptyLabel = "none") {
  if (!items || items.length === 0) {
    return `<span class="subtle">${escapeHtml(emptyLabel)}</span>`;
  }
  return items.map(item => `<span class="badge ${className}">${escapeHtml(item)}</span>`).join("");
}

function confidenceBadgeList(items, confidences = {}, className = "") {
  const labels = (items || []).map(item => {
    const confidence = Number(confidences[item]);
    return Number.isFinite(confidence) ? `${item}:${confidence.toFixed(2)}` : item;
  });
  return badgeList(labels, className);
}

function techniqueBadgeList(techniques, confidences = {}) {
  return confidenceBadgeList(techniques, confidences, "warn");
}

function assetConfigurationLabels(assets) {
  return (assets || []).flatMap(asset => {
    const assetId = asset.asset_id || asset.asset_name || "asset";
    const configurationIds = asset.active_configuration_ids || [];
    return configurationIds.map(configurationId => `${assetId}:${configurationId}`);
  });
}

function compactLabels(items) {
  return (items || []).filter(item => item && item !== "-");
}

function decisionConfigurationLabels(decisions) {
  const labels = [];
  (decisions || []).forEach(decision => {
    (decision.actions || []).forEach(action => {
      if (action.configuration_id) {
        labels.push(`${action.asset_id}:${action.configuration_id}`);
      }
    });
    (decision.route_updates || []).forEach(update => {
      const text = String(update || "");
      const match = text.match(/\bconfigures\s+([^\s]+)/);
      if (match) {
        labels.push(match[1]);
      }
    });
  });
  return [...new Set(labels)];
}

function attackerActivityLabels(attacker) {
  const commands = (attacker.commands || []).map(command => `cmd:${command}`);
  const publicEvidence = (attacker.public_http_evidence || []).map(item => `public:${item}`);
  const internalEvidence = (attacker.internal_http_evidence || []).map(item => `internal:${item}`);
  const configs = [
    ...assetConfigurationLabels(attacker.current_running_assets || []),
    ...decisionConfigurationLabels(attacker.decisions || []),
  ].map(item => `config:${item}`);
  return [...new Set([...commands, ...publicEvidence, ...internalEvidence, ...configs])];
}

function decisionTargetLabel(event) {
  if (event.configuration_id && event.asset_id) {
    return `${event.asset_id}:${event.configuration_id}`;
  }
  return event.asset_id || "";
}

function revealOptionLabel(option) {
  const target = option.configuration_id
    ? `${option.asset_id}:${option.configuration_id}`
    : option.asset_id;
  return `${option.action_type || "reveal"} ${target || ""}`.trim();
}

function countLabels(counts) {
  return Object.entries(counts || {}).map(([label, count]) => {
    const noun = Number(count) === 1 ? "asset" : "assets";
    return `${count} ${noun} rejected: ${formatRejectionReason(label)}`;
  });
}

function gainTermLabels(event) {
  const terms = Array.isArray(event.gain_terms) ? event.gain_terms : [];
  if (terms.length) {
    return terms.map(term => {
      const technique = term.technique || "technique";
      const support = Number(term.support);
      const confidence = Number(term.confidence);
      const gain = Number(term.gain);
      const details = [
        Number.isFinite(support) ? `s${support.toFixed(2)}` : "",
        Number.isFinite(confidence) ? `c${confidence.toFixed(2)}` : "",
        Number.isFinite(gain) ? `g${gain.toFixed(2)}` : "",
      ].filter(Boolean).join(" ");
      return details ? `${technique} ${details}` : technique;
    });
  }
  return event.covered_techniques || [];
}

function formatRejectionReason(reason) {
  const text = String(reason || "");
  const dependencyMatch = text.match(/^missing dependencies:\s*\[(.*)\]$/);
  if (!dependencyMatch) {
    return text;
  }
  const dependencies = dependencyMatch[1]
    .split(",")
    .map(item => item.trim().replace(/^['"]|['"]$/g, ""))
    .filter(Boolean);
  if (!dependencies.length) {
    return "waiting for required dependency";
  }
  const noun = dependencies.length === 1 ? "dependency" : "dependencies";
  return `waiting for ${noun}: ${dependencies.join(", ")}`;
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
      const latestDecisionParts = latestDecisionEvents.length
        ? latestDecisionEvents.flatMap(event => compactLabels([decisionTargetLabel(event), event.selected_technique]))
        : (latestDecision.reasons || []);
      const latestDecisionLabel = compactLabels(latestDecisionParts).join(", ");
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
          <div class="kv"><div class="key">Tactics</div><div>${confidenceBadgeList(attacker.recent_tactics || [], attacker.confidence_by_tactic || {})}</div></div>
          <div class="kv"><div class="key">Techniques</div><div>${techniqueBadgeList(attacker.recent_techniques || [], attacker.confidence_by_technique || {})}</div></div>
          <div class="kv"><div class="key">Recent Activity</div><div>${badgeList(attackerActivityLabels(attacker))}</div></div>
          <div class="kv"><div class="key">Unlocked</div><div>${badgeList(attacker.unlocked_assets || [])}</div></div>
          <div class="kv"><div class="key">Configured</div><div>${badgeList(assetConfigurationLabels(attacker.current_running_assets || []), "warn")}</div></div>
          <div class="kv"><div class="key">Failed</div><div>${badgeList((attacker.failed_assets || []).map(asset => `${asset.asset_id} ${asset.failure_detail || asset.current_container_status || "failed"}`), "bad")}</div></div>
          <div class="kv decision-kv"><div class="key">Decision Trace</div><div>${renderDecisions(attacker.decisions || [], attacker.attacker_key || "-", attacker.confidence_by_technique || {})}</div></div>
        </div>
      </details>
    `;
    }).join("")}
  </div>`;
}

function decisionSortKey(decision) {
  return String(decision.ts || "");
}

function renderDecisions(decisions, attackerKey, confidences = {}) {
  if (!decisions.length) {
    return '<span class="subtle">none</span>';
  }
  const newestFirst = decisions
    .slice()
    .sort((left, right) => decisionSortKey(right).localeCompare(decisionSortKey(left)));
  return `<div class="decision-list">
    ${newestFirst.map(decision => renderDecision(decision, attackerKey, confidences)).join("")}
  </div>`;
}

function renderDecision(decision, attackerKey, confidences = {}) {
  const events = decision.decision_events || [];
  const isWaitingOnly = events.length > 0 && events.every(event => event.no_reveal_reason === "waiting_for_reveal_response");
  const hasRevealAction = (decision.actions || []).some(action => action.action_type && action.action_type !== "noop");
  const eventRows = events.length
    ? events.map(event => renderDecisionEvent(event)).join("")
    : `<div class="decision-row">${badgeList(decision.reasons || [], "warn")}</div>`;
  const actionLabels = (decision.actions || []).map(action => {
    const target = action.configuration_id
      ? `${action.asset_id}:${action.configuration_id}`
      : action.asset_id;
    return `${action.action_type || "action"} ${target || ""}`.trim();
  });
  const droppedLabels = (decision.dropped_actions || []).map(action => `${action.action_type || "action"} ${action.asset_id || ""}`.trim());
  const droppedHtml = droppedLabels.length
    ? `<span>dropped ${badgeList(droppedLabels, "bad")}</span>`
    : "";
  const actionHtml = actionLabels.some(label => label !== "noop")
    ? `<span>actions ${badgeList(actionLabels, "", "no reveal actions")}</span>`
    : "";
  const footerHtml = actionHtml || droppedHtml
    ? `<div class="decision-actions subtle">${actionHtml}${droppedHtml}</div>`
    : "";
  const detailKey = `decision:${attackerKey}:${decision.ts || "-"}:${actionLabels.join("|")}`;
  const triggerLabels = (decision.trigger_evidence || []).map(item => item.text || item.evidence_id).filter(Boolean);
  const triggerLine = triggerLabels.length
    ? `<span class="trace-trigger"><span class="trace-label">Triggered by</span>${badgeList(triggerLabels)}</span>`
    : "";
  if (isWaitingOnly) {
    return `<div class="decision-block decision-waiting">
      <div class="decision-meta">
        <span class="trace-summary"><span class="trace-dot trace-dot-wait"></span><span class="mono">${escapeHtml(decision.ts || "-")}</span></span>
        ${triggerLine}
        <span class="badge">waiting for response</span>
      </div>
    </div>`;
  }
  return `<details class="decision-block" data-detail-key="${escapeHtml(detailKey)}"${detailOpenAttribute(detailKey, hasRevealAction)}>
    <summary class="decision-meta">
      <span class="trace-summary"><span class="trace-dot"></span><span class="mono">${escapeHtml(decision.ts || "-")}</span></span>
      ${triggerLine}
      <span class="trace-observed"><span class="trace-label">Observed</span>${techniqueBadgeList(decision.recent_techniques || [], confidences)}</span>
    </summary>
    ${eventRows}
    ${footerHtml}
  </details>`;
}

function renderDecisionEvent(event) {
  const gain = event.expected_technique_gain === null || event.expected_technique_gain === undefined
    ? "0.00"
    : Number(event.expected_technique_gain).toFixed(2);
  const gainTerms = gainTermLabels(event);
  const eligibleLabels = (event.eligible_reveal_options || []).map(revealOptionLabel);
  const rejectionLabels = countLabels(event.rejection_reason_counts);
  const priorState = event.prior_support_enabled === false
    ? "disabled"
    : (event.prior_degraded ? `degraded: ${event.prior_degraded}` : "active");
  const roleLabel = event.reveal_role === "explore"
    ? "explore lane"
    : (event.reveal_role === "main" ? "main lane" : "no reveal lane");
  const techniqueSource = event.candidate_type === "recommended"
    ? "from ATT&CK prior"
    : (event.candidate_type === "observed" ? "from observed profile" : event.candidate_type || "not selected");
  const actionLabel = compactLabels([
    event.decision_type,
    decisionTargetLabel(event),
    event.no_reveal_reason,
  ]).join(" ");
  return `<div class="decision-flow">
    <div class="trace-lane">
      <div class="trace-label">Gate</div>
      <div class="trace-content">
        <div>${badgeList(eligibleLabels, "", "no eligible reveal options")}</div>
        <div class="subtle">eligible options: ${escapeHtml(event.eligible_reveal_option_count ?? 0)} | rejected assets: ${escapeHtml(event.rejected_asset_count ?? 0)}</div>
        <div class="subtle">${badgeList(rejectionLabels, "bad", "no rejected assets")}</div>
        <div class="subtle">matched signals: ${badgeList(event.matched_dependency_markers || [], "", "no matched dependency signals")}</div>
      </div>
    </div>
    <div class="trace-arrow" aria-hidden="true">→</div>
    <div class="trace-lane">
      <div class="trace-label">Rank</div>
      <div class="trace-content">
        <div>${badgeList([roleLabel], "warn")}</div>
        <div class="subtle">strategy ${escapeHtml(event.strategy || "not selected")} | candidate ${escapeHtml(techniqueSource)}</div>
        <div class="subtle">gain terms: ${badgeList(gainTerms, "", "no covered techniques")}</div>
        <div class="subtle">score: total gain ${escapeHtml(gain)} over covered techniques; prior ${escapeHtml(priorState)}</div>
      </div>
    </div>
    <div class="trace-arrow" aria-hidden="true">→</div>
    <div class="trace-lane trace-action">
      <div class="trace-label">Action</div>
      <div class="trace-content">
        <div>${badgeList(actionLabel ? [actionLabel] : [], event.decision_type === "noop" ? "bad" : "", "no action selected")}</div>
        <div class="subtle">${escapeHtml(event.reason || "")}</div>
      </div>
    </div>
  </div>`;
}

function renderActivityTable(records) {
  if (!records.length) {
    return '<div class="empty">No events yet.</div>';
  }
  return `<table>
    <thead>
      <tr><th>Time</th><th>Attacker</th><th>Source</th><th>Event</th><th>Detail</th><th>Evidence</th></tr>
    </thead>
    <tbody>
      ${records.map(record => `
        <tr>
          <td class="mono">${escapeHtml(record.ts || "-")}</td>
          <td class="mono">${escapeHtml(record.attacker || "-")}</td>
          <td>${escapeHtml(record.source || "-")}</td>
          <td>${escapeHtml(record.event || "-")}</td>
          <td class="mono">${escapeHtml(record.detail || "-")}</td>
          <td>${escapeHtml(record.evidence || "-")}</td>
        </tr>
      `).join("")}
    </tbody>
  </table>`;
}

function activityTimestamp(record) {
  return record.ts || record.timestamp || record.utc_time || "-";
}

function buildRecentActivity(data) {
  const rows = [];
  (data.recent_entrypoint_observations || []).forEach(row => {
    rows.push({
      ts: activityTimestamp(row),
      attacker: row.attacker_key || "-",
      source: "public-http",
      event: `${row.method || "HTTP"} ${row.path || "-"}`,
      detail: `status ${row.response_status ?? "-"}`,
      evidence: [...(row.matched_rules || []), ...(row.indicators || [])].join(", "),
    });
  });
  (data.recent_cowrie_observations || []).forEach(row => {
    rows.push({
      ts: activityTimestamp(row),
      attacker: row.attacker_key || row.src_ip || "-",
      source: "cowrie",
      event: row.eventid || "-",
      detail: row.command || "-",
      evidence: row.session || "-",
    });
  });
  (data.recent_opencanary_observations || []).forEach(row => {
    rows.push({
      ts: activityTimestamp(row),
      attacker: row.attacker_key || row.src_host || "-",
      source: "opencanary",
      event: row.service || "-",
      detail: `port ${row.dst_port ?? "-"}`,
      evidence: row.username ? `user ${row.username}` : (row.password_seen ? "password seen" : ""),
    });
  });
  (data.recent_high_interaction_observations || []).forEach(row => {
    rows.push({
      ts: activityTimestamp(row),
      attacker: row.attacker_key || row.src_ip || "-",
      source: row.source || "high-interaction",
      event: row.service || row.event_type || row.eventid || "-",
      detail: row.path || row.command || row.signature || "-",
      evidence: row.asset_id || row.category || "",
    });
  });
  (data.attackers || []).forEach(attacker => {
    (attacker.historical_opened_assets || []).forEach(asset => {
      (asset.active_configuration_ids || []).forEach(configurationId => {
        rows.push({
          ts: asset.started_at || "-",
          attacker: attacker.attacker_key || "-",
          source: "runtime",
          event: "configured runtime",
          detail: `${asset.asset_id || "asset"}:${configurationId}`,
          evidence: asset.image || asset.runtime_backend || "",
        });
      });
    });
    (attacker.decisions || []).forEach(decision => {
      (decision.actions || []).forEach(action => {
        const target = action.configuration_id
          ? `${action.asset_id}:${action.configuration_id}`
          : action.asset_id;
        rows.push({
          ts: decision.ts || "-",
          attacker: attacker.attacker_key || "-",
          source: "controller",
          event: action.action_type || "action",
          detail: target || "-",
          evidence: (decision.recent_techniques || []).join(", "),
        });
      });
      (decision.route_updates || []).forEach(update => {
        rows.push({
          ts: decision.ts || "-",
          attacker: attacker.attacker_key || "-",
          source: "orchestrator",
          event: "route update",
          detail: update || "-",
          evidence: "",
        });
      });
    });
  });
  return rows
    .sort((left, right) => String(left.ts).localeCompare(String(right.ts)))
    .slice(0, 60);
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
  replacePanelHtml("activity-panel", renderActivityTable(buildRecentActivity(data)));
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
