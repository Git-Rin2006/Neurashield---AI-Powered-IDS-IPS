/**
 * NeuraShield Production Console & Active IPS JavaScript App
 * Version 2.4 - Full Production Multi-Tab Interface
 */

let topologyState = null;
let trafficChart = null;
let threatChart = null;
let currentFilterIP = "";
let currentActiveTab = "tab-overview";

document.addEventListener("DOMContentLoaded", () => {
    // Clock Initialization
    updateClock();
    setInterval(updateClock, 1000);

    // Initial Setup
    initTabs();
    initCharts();

    // Initial Data Fetching
    fetchDashboardData();
    fetchBlockedIPs();
    fetchRules();

    // Auto Refresh Polling (every 3 seconds)
    setInterval(pollActiveTabData, 3000);

    // Header Event Listeners
    document.getElementById("btn-refresh-data").addEventListener("click", () => {
        pollActiveTabData(true);
    });
    document.getElementById("btn-clear-logs").addEventListener("click", handleClearLogs);
    document.getElementById("filter-severity").addEventListener("change", fetchIncidents);
});

/* ==========================================================================
   NAVIGATION TAB SYSTEM
   ========================================================================== */

function initTabs() {
    const tabButtons = document.querySelectorAll(".nav-tab-btn");
    tabButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetTab = btn.getAttribute("data-tab");
            switchTab(targetTab);
        });
    });
}

function switchTab(tabId) {
    currentActiveTab = tabId;

    // Update Tab Buttons UI
    document.querySelectorAll(".nav-tab-btn").forEach(btn => {
        if (btn.getAttribute("data-tab") === tabId) {
            btn.classList.add("active");
        } else {
            btn.classList.remove("active");
        }
    });

    // Update Tab Panels UI
    document.querySelectorAll(".tab-panel").forEach(panel => {
        if (panel.id === tabId) {
            panel.classList.add("active");
        } else {
            panel.classList.remove("active");
        }
    });

    // Fetch tab-specific data on switch
    pollActiveTabData(true);
}

function pollActiveTabData(forceAll = false) {
    // Always fetch overview status for metric cards & header
    fetchSystemStatus();
    fetchBlockedIPs();

    if (currentActiveTab === "tab-overview" || forceAll) {
        fetchDashboardData();
    }
    if (currentActiveTab === "tab-flows" || forceAll) {
        fetchActiveFlows();
    }
    if (currentActiveTab === "tab-db-logs" || forceAll) {
        fetchIncidents();
    }
    if (currentActiveTab === "tab-ips-rules" || forceAll) {
        fetchRules();
    }
}

/* ==========================================================================
   OVERVIEW & TELEMETRY TAB LOGIC
   ========================================================================== */

function updateClock() {
    const now = new Date();
    document.getElementById("live-clock").textContent = now.toLocaleTimeString();
}

function initCharts() {
    // Traffic Time Series Chart
    const ctxTraffic = document.getElementById("chart-traffic").getContext("2d");
    trafficChart = new Chart(ctxTraffic, {
        type: "line",
        data: {
            labels: [],
            datasets: [{
                label: "Active Flows",
                data: [],
                borderColor: "#00f2fe",
                backgroundColor: "rgba(0, 242, 254, 0.1)",
                borderWidth: 2,
                fill: true,
                tension: 0.3
            }, {
                label: "Accepted Packets",
                data: [],
                borderColor: "#38bdf8",
                backgroundColor: "transparent",
                borderWidth: 1.5,
                borderDash: [4, 4],
                tension: 0.3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: "#94a3b8" } }
            },
            scales: {
                x: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#64748b" } },
                y: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#64748b" }, beginAtZero: true }
            }
        }
    });

    // Threat Distribution Doughnut Chart
    const ctxThreats = document.getElementById("chart-threats").getContext("2d");
    threatChart = new Chart(ctxThreats, {
        type: "doughnut",
        data: {
            labels: ["No Data"],
            datasets: [{
                data: [1],
                backgroundColor: ["#334155", "#00f2fe", "#f59e0b", "#ef4444", "#a855f7"],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: "bottom", labels: { color: "#94a3b8" } }
            },
            cutout: "70%"
        }
    });
}

async function fetchSystemStatus() {
    try {
        const resStatus = await fetch("/api/status");
        if (resStatus.ok) {
            const status = await resStatus.json();
            document.getElementById("val-packets").textContent = (status.total_packets || 0).toLocaleString();
            document.getElementById("val-flows").textContent = (status.active_flows || 0).toLocaleString();
            document.getElementById("val-threats").textContent = (status.total_incidents || 0).toLocaleString();
        }
    } catch (err) {
        console.error("Failed to fetch system status:", err);
    }
}

async function fetchDashboardData() {
    try {
        // 1. Fetch Topology & Node Status
        const resTopo = await fetch("/api/topology");
        if (resTopo.ok) {
            topologyState = await resTopo.json();
            updateTreeNodes(topologyState);
        }

        // 2. Fetch Grouped Warnings
        fetchGroupedWarnings();

        // 3. Fetch Traffic History
        const resStats = await fetch("/api/stats/traffic?limit=20");
        if (resStats.ok) {
            const data = await resStats.json();
            updateTrafficChart(data.history || []);
        }

        // 4. Fetch Threat Summary
        const resSummary = await fetch("/api/summary");
        if (resSummary.ok) {
            const summary = await resSummary.json();
            updateThreatChart(summary.top_threats || []);
        }
    } catch (err) {
        console.error("Failed to fetch overview dashboard data:", err);
    }
}

function updateTreeNodes(topo) {
    if (!topo) return;

    // Update Tree VM 1
    const treeNodeVm1 = document.getElementById("tree-node-vm1");
    const statusVm1 = document.getElementById("tree-status-vm1");
    const metaVm1 = document.getElementById("tree-meta-vm1");
    if (topo.vm1 && topo.vm1.status === "ALERT") {
        treeNodeVm1.className = "tree-node pc-node alert-node";
        statusVm1.className = "badge-status status-red";
        statusVm1.textContent = "THREAT ALERT";
        metaVm1.innerHTML = `<strong style="color:var(--accent-red);">${topo.vm1.threat_count} alerts (${topo.vm1.latest_threat})</strong>`;
    } else {
        treeNodeVm1.className = "tree-node pc-node";
        statusVm1.className = "badge-status status-green";
        statusVm1.textContent = "ONLINE";
        metaVm1.textContent = "Workstation Node";
    }

    // Update Tree VM 2
    const treeNodeVm2 = document.getElementById("tree-node-vm2");
    const statusVm2 = document.getElementById("tree-status-vm2");
    const metaVm2 = document.getElementById("tree-meta-vm2");
    if (topo.vm2 && topo.vm2.status === "ALERT") {
        treeNodeVm2.className = "tree-node pc-node alert-node";
        statusVm2.className = "badge-status status-red";
        statusVm2.textContent = "THREAT ALERT";
        metaVm2.innerHTML = `<strong style="color:var(--accent-red);">${topo.vm2.threat_count} alerts (${topo.vm2.latest_threat})</strong>`;
    } else {
        treeNodeVm2.className = "tree-node pc-node";
        statusVm2.className = "badge-status status-green";
        statusVm2.textContent = "ONLINE";
        metaVm2.textContent = "Workstation Node";
    }
}

function filterByNode(ipOrKey) {
    const searchInput = document.getElementById("threat-search");
    if (ipOrKey === "VM3") {
        currentFilterIP = "";
        if (searchInput) searchInput.value = "";
    } else {
        currentFilterIP = ipOrKey;
        if (searchInput) searchInput.value = ipOrKey;
    }
    filterThreats();
}

function filterThreats() {
    const query = (document.getElementById("threat-search").value || "").toLowerCase();
    const cards = document.querySelectorAll(".warning-card");

    cards.forEach(card => {
        const text = card.textContent.toLowerCase();
        if (!query || text.includes(query)) {
            card.style.display = "flex";
        } else {
            card.style.display = "none";
        }
    });
}

async function fetchGroupedWarnings() {
    try {
        const res = await fetch("/api/incidents/grouped?limit=15");
        if (!res.ok) return;

        const data = await res.json();
        renderGroupedWarnings(data.alerts || []);
    } catch (err) {
        console.error("Failed to fetch grouped warnings:", err);
    }
}

function renderGroupedWarnings(alerts) {
    const container = document.getElementById("warnings-container");
    if (!alerts || !alerts.length) {
        container.innerHTML = `
            <div class="empty-state glass-card" style="padding:16px; text-align:center;">
                <i class="fa-solid fa-shield-check" style="color:var(--accent-green); font-size:1.5rem; margin-bottom:6px;"></i>
                <p style="font-size:12px; color:var(--text-secondary);">No active threat warnings detected. All connected subnets are running cleanly.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = alerts.map(alt => {
        const sevClass = alt.severity || "HIGH";
        return `
            <div class="warning-card glass-card ${sevClass}">
                <div class="warning-info">
                    <i class="fa-solid fa-triangle-exclamation warning-icon ${sevClass}"></i>
                    <div>
                        <div class="warning-title">
                            <strong>${alt.threat}</strong> 
                            <span class="badge-sev ${sevClass}">${sevClass}</span>
                            <span class="code-tag" style="margin-left:8px;">${alt.rule_id}</span>
                        </div>
                        <div class="warning-subtitle">
                            Traffic Path: <code>${alt.source_ip}</code> ➔ <code>${alt.destination_ip}</code> | ${alt.evidence}
                        </div>
                    </div>
                </div>
                <div class="warning-count-badge">
                    ${alt.count.toLocaleString()} Events
                </div>
            </div>
        `;
    }).join("");

    filterThreats();
}

function updateTrafficChart(history) {
    if (!trafficChart || !history || !history.length) return;

    const labels = history.map(h => {
        const parts = (h.timestamp || "").split(" ");
        return parts[1] || h.timestamp;
    });
    const flows = history.map(h => h.active_flows);
    const packets = history.map(h => h.total_packets);

    trafficChart.data.labels = labels;
    trafficChart.data.datasets[0].data = flows;
    trafficChart.data.datasets[1].data = packets;
    trafficChart.update("none");
}

function updateThreatChart(topThreats) {
    if (!threatChart) return;

    if (!topThreats || !topThreats.length) {
        threatChart.data.labels = ["Clean (No Threats)"];
        threatChart.data.datasets[0].data = [1];
        threatChart.data.datasets[0].backgroundColor = ["#10b981"];
    } else {
        threatChart.data.labels = topThreats.map(t => t.threat);
        threatChart.data.datasets[0].data = topThreats.map(t => t.count);
        threatChart.data.datasets[0].backgroundColor = ["#ef4444", "#f59e0b", "#38bdf8", "#a855f7", "#00f2fe"];
    }
    threatChart.update();
}

/* ==========================================================================
   LIVE PACKET FLOWS TAB LOGIC
   ========================================================================== */

async function fetchActiveFlows() {
    try {
        const res = await fetch("/api/flows/active");
        if (!res.ok) return;

        const data = await res.json();
        renderActiveFlowsTable(data.flows || []);
    } catch (err) {
        console.error("Failed to fetch live active flows:", err);
    }
}

function renderActiveFlowsTable(flows) {
    const tbody = document.getElementById("flows-tbody");
    if (!tbody) return;

    if (!flows || !flows.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center py-4 text-muted">
                    <i class="fa-solid fa-circle-info" style="color:var(--accent-blue); font-size:1.5rem; margin-bottom:4px;"></i><br>
                    No active TCP/UDP/ICMP 5-tuple packet flows detected in current 5s window.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = flows.map(f => {
        const protoLabel = f.protocol === 6 ? "TCP" : f.protocol === 17 ? "UDP" : f.protocol === 1 ? "ICMP" : f.protocol;
        const durSec = ((f.flow_duration_ms || 0) / 1000).toFixed(2);
        const pktRate = (f.packet_rate || (f.total_packets / (durSec || 1))).toFixed(1);
        const byteRate = (f.byte_rate || (f.total_bytes / (durSec || 1))).toFixed(1);

        return `
            <tr>
                <td><code>${f.source_ip}:${f.source_port}</code></td>
                <td><code>${f.destination_ip}:${f.destination_port}</code></td>
                <td><span class="code-tag">${protoLabel}</span></td>
                <td>${durSec} s</td>
                <td><strong>${f.total_packets}</strong> pkts</td>
                <td>${(f.total_bytes || 0).toLocaleString()} B</td>
                <td>${pktRate} /s</td>
                <td>${byteRate} B/s</td>
                <td>${f.syn_count || 0} / ${f.ack_count || 0}</td>
            </tr>
        `;
    }).join("");
}

/* ==========================================================================
   DATABASE LOG EXPLORER TAB LOGIC
   ========================================================================== */

async function fetchIncidents() {
    const sevFilter = document.getElementById("filter-severity").value;
    const searchVal = (document.getElementById("log-search") ? document.getElementById("log-search").value : "").trim();
    
    let url = "/api/incidents?limit=50";
    if (sevFilter) url += `&severity=${sevFilter}`;

    try {
        const res = await fetch(url);
        if (!res.ok) return;

        const data = await res.json();
        let incidents = data.incidents || [];

        // Apply client-side text search filter
        if (searchVal) {
            const query = searchVal.toLowerCase();
            incidents = incidents.filter(i => 
                (i.source_ip || "").toLowerCase().includes(query) ||
                (i.destination_ip || "").toLowerCase().includes(query) ||
                (i.threat || "").toLowerCase().includes(query) ||
                (i.rule_id || "").toLowerCase().includes(query) ||
                (i.evidence || "").toLowerCase().includes(query)
            );
        }

        renderIncidentsTable(incidents);
    } catch (err) {
        console.error("Failed to fetch raw audit logs:", err);
    }
}

function renderIncidentsTable(incidents) {
    const tbody = document.getElementById("incidents-tbody");
    if (!tbody) return;

    if (!incidents || !incidents.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" class="text-center py-4 text-muted">
                    <i class="fa-solid fa-shield-check" style="color:var(--accent-green); font-size:1.5rem;"></i><br>
                    No raw SQLite log records matching current filter.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = incidents.map(inc => {
        const sevClass = inc.severity || "HIGH";
        return `
            <tr>
                <td style="font-family:var(--font-mono); font-size:11px;">#${inc.id}</td>
                <td style="white-space:nowrap; font-family:var(--font-mono); font-size:12px;">${inc.timestamp || "-"}</td>
                <td><span class="code-tag">${inc.rule_id || "RULE"}</span></td>
                <td><strong>${inc.threat || "UNKNOWN"}</strong></td>
                <td><span class="badge-sev ${sevClass}">${sevClass}</span></td>
                <td>${inc.confidence || 90}%</td>
                <td><code>${inc.source_ip || "-"}</code></td>
                <td><code>${inc.destination_ip || "-"}</code></td>
                <td style="max-width:280px; font-size:11px; white-space:normal;" title="${inc.evidence}">${inc.evidence || "-"}</td>
            </tr>
        `;
    }).join("");
}

function exportCSVLog() {
    window.location.href = "/api/logs/export";
}

async function handleClearLogs() {
    if (!confirm("Clear all historical threat logs from SQLite database and reset node states?")) return;
    try {
        const res = await fetch("/api/incidents/clear", { method: "POST" });
        if (res.ok) {
            pollActiveTabData(true);
        }
    } catch (err) {
        console.error("Failed to clear logs:", err);
    }
}

/* ==========================================================================
   IPS FIREWALL & RULES TAB LOGIC
   ========================================================================== */

async function fetchBlockedIPs() {
    try {
        const res = await fetch("/api/ips/blocked");
        if (!res.ok) return;

        const data = await res.json();
        
        // Update header metric card
        const valBlocked = document.getElementById("val-blocked");
        if (valBlocked) {
            valBlocked.textContent = (data.active_count || 0).toLocaleString();
        }

        renderBlockedIPsTable(data.history || []);
    } catch (err) {
        console.error("Failed to fetch blocked IPs:", err);
    }
}

function renderBlockedIPsTable(history) {
    const tbody = document.getElementById("blocked-tbody");
    if (!tbody) return;

    if (!history || !history.length) {
        tbody.innerHTML = `
            <tr>
                <td colspan="8" class="text-center py-4 text-muted">
                    <i class="fa-solid fa-shield-halved" style="color:var(--accent-green); font-size:1.5rem; margin-bottom:4px;"></i><br>
                    No hosts currently in IPS firewall quarantine.
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = history.map(item => {
        const isActive = item.is_active === 1;
        const statusBadge = isActive 
            ? `<span class="badge-status status-red"><i class="fa-solid fa-fire"></i> ACTIVE DROP</span>`
            : `<span class="badge-status status-green"><i class="fa-solid fa-check"></i> EXPIRED / UNBLOCKED</span>`;

        const actionBtn = isActive
            ? `<button class="btn btn-secondary" style="padding:4px 10px; font-size:11px; background:rgba(16,185,129,0.15); color:var(--accent-green); border-color:rgba(16,185,129,0.4);" onclick="handleUnblock('${item.ip}')">
                <i class="fa-solid fa-key"></i> Unblock Host
               </button>`
            : `<span class="text-muted" style="font-size:11px;">None</span>`;

        return `
            <tr>
                <td><code>${item.ip}</code></td>
                <td><strong>${item.threat || "IPS_RULE_TRIGGER"}</strong></td>
                <td><span class="badge-sev ${item.severity || 'HIGH'}">${item.severity || 'HIGH'}</span></td>
                <td style="white-space:nowrap; font-family:var(--font-mono); font-size:11px;">${item.blocked_at || "-"}</td>
                <td style="white-space:nowrap; font-family:var(--font-mono); font-size:11px;">${item.unblock_at || "PERMANENT"}</td>
                <td><span class="code-tag">${item.action_by || "AUTOMATED_IPS"}</span></td>
                <td>${statusBadge}</td>
                <td>${actionBtn}</td>
            </tr>
        `;
    }).join("");
}

async function handleManualBlock(event) {
    event.preventDefault();
    const targetIp = document.getElementById("block-target-ip").value.trim();
    const reason = document.getElementById("block-reason").value.trim() || "MANUAL_ADMIN_BLOCK";
    const duration = document.getElementById("block-duration").value;

    if (!targetIp) return;

    try {
        const url = `/api/ips/block?ip=${encodeURIComponent(targetIp)}&threat=${encodeURIComponent(reason)}&duration=${duration}`;
        const res = await fetch(url, { method: "POST" });
        const data = await res.json();

        if (res.ok) {
            alert(`IP ${targetIp} has been quarantined in Linux iptables.`);
            document.getElementById("block-target-ip").value = "";
            document.getElementById("block-reason").value = "";
            fetchBlockedIPs();
        } else {
            alert(`Failed to block IP: ${data.detail || data.message || "Unknown error"}`);
        }
    } catch (err) {
        console.error("Error manual block IP:", err);
        alert("Server error when attempting to block IP.");
    }
}

async function handleUnblock(ip) {
    if (!confirm(`Are you sure you want to remove iptables DROP rule and unblock ${ip}?`)) return;

    try {
        const url = `/api/ips/unblock?ip=${encodeURIComponent(ip)}`;
        const res = await fetch(url, { method: "POST" });
        if (res.ok) {
            fetchBlockedIPs();
        } else {
            alert("Failed to unblock IP.");
        }
    } catch (err) {
        console.error("Error unblocking IP:", err);
    }
}

async function fetchRules() {
    try {
        const res = await fetch("/api/rules");
        if (!res.ok) return;

        const data = await res.json();
        renderRulesTable(data.heuristic_rules || []);
        renderMLStatus(data.ml_status || {});
    } catch (err) {
        console.error("Failed to fetch detection rules:", err);
    }
}

function renderRulesTable(rules) {
    const tbody = document.getElementById("rules-tbody");
    if (!tbody) return;

    if (!rules || !rules.length) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-muted">No rules registered.</td></tr>`;
        return;
    }

    tbody.innerHTML = rules.map(r => `
        <tr>
            <td><span class="code-tag">${r.id}</span></td>
            <td><strong>${r.name}</strong></td>
            <td style="font-family:var(--font-mono); font-size:12px;">${r.threshold}</td>
            <td><span class="badge-sev ${r.severity}">${r.severity}</span></td>
        </tr>
    `).join("");
}

function renderMLStatus(ml) {
    const box = document.getElementById("ml-status-box");
    if (!box) return;

    box.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:12px;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span>Layer 1 Heuristic Threshold Detector</span>
                <span class="badge-status status-green"><i class="fa-solid fa-check"></i> ACTIVE</span>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span>Layer 2 Random Forest ML Model (NSL-KDD)</span>
                ${ml.layer2_random_forest_loaded 
                    ? `<span class="badge-status status-green"><i class="fa-solid fa-check"></i> LOADED (99.2% Acc)</span>` 
                    : `<span class="badge-status status-red"><i class="fa-solid fa-xmark"></i> NOT LOADED</span>`}
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span>Layer 3 Online Self-Learning Anomaly Model</span>
                ${ml.layer3_self_learning_loaded 
                    ? `<span class="badge-status status-green"><i class="fa-solid fa-check"></i> ADAPTIVE LEARNING</span>` 
                    : `<span class="badge-status status-red"><i class="fa-solid fa-xmark"></i> INACTIVE</span>`}
            </div>
            <hr style="border:0; border-top:1px solid var(--glass-border); margin:4px 0;">
            <div style="font-size:12px; color:var(--text-secondary);">
                <strong>Training Base:</strong> ${ml.dataset_trained || "NSL-KDD Cleaned Benchmark Dataset"}<br>
                <strong>Evaluation Pipeline:</strong> Sequential Multi-Tier Pipeline (Heuristic Heuristics ➔ ML Classifier ➔ Firewall IPS Auto-Quarantine)
            </div>
        </div>
    `;
}
