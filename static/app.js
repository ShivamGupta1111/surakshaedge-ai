document.addEventListener("DOMContentLoaded", () => {
    initNavigation();
    initVectorSelector();
    initForms();
    fetchSystemInfo();
});

// TAB NAVIGATION
function initNavigation() {
    const tabs = document.querySelectorAll(".nav-tab");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));
            
            tab.classList.add("active");
            const target = tab.dataset.tab;
            document.getElementById(`tab-${target}`).classList.add("active");

            if (target === "alerts") loadAlerts();
            if (target === "metrics") loadMetrics();
        });
    });
}

// VECTOR SELECTOR
function initVectorSelector() {
    const btns = document.querySelectorAll(".vector-btn");
    btns.forEach(btn => {
        btn.addEventListener("click", () => {
            btns.forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".vector-form").forEach(f => f.classList.remove("active"));

            btn.classList.add("active");
            const vector = btn.dataset.vector;
            document.getElementById(`form-${vector}`).classList.add("active");
        });
    });
}

// PRESET HELPERS
function setSmsPreset(type) {
    const input = document.getElementById("sms-text");
    if (type === "phishing") {
        input.value = "URGENT: your bank account will be suspended. Confirm password & OTP immediately at http://bit.ly/verify-now";
    } else if (type === "scam") {
        input.value = "Congratulations you won a lottery prize of 50 Lakhs! Claim now or lose it. Pay processing fee via UPI.";
    } else {
        input.value = "Meeting moved to 4pm in conference room B. Please bring your notes.";
    }
}

function setUrlPreset(type) {
    const input = document.getElementById("url-text");
    if (type === "benign") {
        input.value = "https://example.com/docs/help";
    } else if (type === "phishing") {
        input.value = "http://192.0.2.55/login/verify-account/wallet";
    } else {
        input.value = "http://paypa1-secure-login.top/verify";
    }
}

function setNetPreset(type) {
    if (type === "normal") {
        document.getElementById("net-duration").value = "0.5";
        document.getElementById("net-protocol").value = "tcp";
        document.getElementById("net-src-port").value = "49152";
        document.getElementById("net-dst-port").value = "443";
        document.getElementById("net-fwd-packets").value = "8";
        document.getElementById("net-bwd-packets").value = "10";
        document.getElementById("net-packet-rate").value = "20";
        document.getElementById("net-failed-count").value = "0";
        document.getElementById("net-syn-count").value = "1";
    } else {
        document.getElementById("net-duration").value = "0.1";
        document.getElementById("net-protocol").value = "tcp";
        document.getElementById("net-src-port").value = "1234";
        document.getElementById("net-dst-port").value = "4444";
        document.getElementById("net-fwd-packets").value = "40";
        document.getElementById("net-bwd-packets").value = "0";
        document.getElementById("net-packet-rate").value = "2500";
        document.getElementById("net-failed-count").value = "12";
        document.getElementById("net-syn-count").value = "40";
    }
}

// FORM SUBMISSIONS
function initForms() {
    document.getElementById("form-sms").addEventListener("submit", async (e) => {
        e.preventDefault();
        const msg = document.getElementById("sms-text").value;
        await runAnalysis("/api/v1/analyze/message", { message: msg }, "btn-scan-sms");
    });

    document.getElementById("form-url").addEventListener("submit", async (e) => {
        e.preventDefault();
        const url = document.getElementById("url-text").value;
        await runAnalysis("/api/v1/analyze/url", { url: url }, "btn-scan-url");
    });

    document.getElementById("form-network").addEventListener("submit", async (e) => {
        e.preventDefault();
        const payload = {
            duration: parseFloat(document.getElementById("net-duration").value),
            protocol: document.getElementById("net-protocol").value,
            src_port: parseInt(document.getElementById("net-src-port").value, 10),
            dst_port: parseInt(document.getElementById("net-dst-port").value, 10),
            fwd_packets: parseInt(document.getElementById("net-fwd-packets").value, 10),
            bwd_packets: parseInt(document.getElementById("net-bwd-packets").value, 10),
            packet_rate: parseFloat(document.getElementById("net-packet-rate").value),
            failed_count: parseInt(document.getElementById("net-failed-count").value, 10),
            syn_count: parseInt(document.getElementById("net-syn-count").value, 10)
        };
        await runAnalysis("/api/v1/analyze/network-flow", payload, "btn-scan-net");
    });

    document.getElementById("form-telemetry").addEventListener("submit", async (e) => {
        e.preventDefault();
        const payload = {
            unexpected_process_spawn_count: parseInt(document.getElementById("tel-proc").value, 10),
            persistence_attempts: parseInt(document.getElementById("tel-persist").value, 10),
            failed_auth_count: parseInt(document.getElementById("tel-failed-auth").value, 10),
            suspicious_path_execution: document.getElementById("tel-suspicious-path").value === "true"
        };
        await runAnalysis("/api/v1/analyze/telemetry", payload, "btn-scan-tel");
    });
}

// CALL API & RENDER RESULT
async function runAnalysis(endpoint, payload, btnId) {
    const btn = document.getElementById(btnId);
    const originalText = btn.innerHTML;
    btn.innerHTML = `<span class="btn-text">Scanning...</span>`;
    btn.disabled = true;

    try {
        const res = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });

        if (!res.ok) {
            const err = await res.json();
            alert(`Analysis Error: ${err.error || 'Server error'}`);
            return;
        }

        const data = await res.json();
        renderResult(data);
    } catch (err) {
        alert(`Network Error: ${err.message}`);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

function renderResult(data) {
    document.getElementById("result-empty").classList.add("hidden");
    document.getElementById("result-content").classList.remove("hidden");

    // Risk Badge & Header
    const level = (data.risk_level || "low").toLowerCase();
    const badge = document.getElementById("res-risk-level");
    badge.className = `badge ${level}`;
    badge.innerText = level.toUpperCase();

    document.getElementById("res-primary-threat").innerText = (data.primary_threat || "Threat").toUpperCase() + " ASSESSMENT";
    document.getElementById("res-score-num").innerText = data.risk_score.toFixed(2);
    
    // Gauge Bar Color & Width
    const gauge = document.getElementById("res-gauge-bar");
    const pct = Math.min(100, Math.max(5, Math.round(data.risk_score * 100)));
    gauge.style.width = `${pct}%`;
    if (level === "low") gauge.style.backgroundColor = "var(--risk-low)";
    else if (level === "medium") gauge.style.backgroundColor = "var(--risk-medium)";
    else if (level === "high") gauge.style.backgroundColor = "var(--risk-high)";
    else gauge.style.backgroundColor = "var(--risk-critical)";

    // Stats
    document.getElementById("res-confidence").innerText = `${Math.round(data.confidence * 100)}%`;
    const det = data.detectors && data.detectors[0] ? data.detectors[0] : {};
    document.getElementById("res-detector-name").innerText = det.detector || "-";
    document.getElementById("res-model-version").innerText = det.model_version || "-";
    document.getElementById("res-advisor-backend").innerText = data.advisor_backend || "local_template";

    // Action
    document.getElementById("res-action-text").innerText = det.recommended_action || (data.recommended_actions && data.recommended_actions[0]) || "No immediate action needed.";

    // Evidence Tags
    const tagsContainer = document.getElementById("res-evidence-tags");
    tagsContainer.innerHTML = "";
    const evidenceList = data.evidence || [];
    if (evidenceList.length === 0) {
        tagsContainer.innerHTML = `<span class="tag-chip">no_high_risk_indicators</span>`;
    } else {
        evidenceList.forEach(item => {
            const span = document.createElement("span");
            span.className = "tag-chip";
            span.innerText = item;
            tagsContainer.appendChild(span);
        });
    }

    // Llama Advisor
    const adv = data.advice || {};
    document.getElementById("res-adv-title").innerText = adv.title || "Advisor Guidance";
    document.getElementById("res-adv-explanation").innerText = adv.explanation || "No explanation provided.";

    const concernedUl = document.getElementById("res-adv-concerned");
    concernedUl.innerHTML = "";
    (adv.why_concerned || []).forEach(reason => {
        const li = document.createElement("li");
        li.innerText = reason;
        concernedUl.appendChild(li);
    });

    const actionsUl = document.getElementById("res-adv-actions");
    actionsUl.innerHTML = "";
    (adv.immediate_actions || []).forEach(act => {
        const li = document.createElement("li");
        li.innerText = act;
        actionsUl.appendChild(li);
    });

    document.getElementById("res-adv-uncertainty").innerText = adv.uncertainty_statement || "";
    document.getElementById("res-adv-disclaimer").innerText = adv.disclaimer || "Advisory output only.";
}

// FETCH SYSTEM INFO
async function fetchSystemInfo() {
    try {
        const res = await fetch("/api/v1/info");
        if (res.ok) {
            const data = await res.json();
            document.getElementById("advisor-backend-label").innerText = `Advisor: ${data.advisor_backend}`;
        }
    } catch (e) {
        console.warn("Could not fetch info:", e);
    }
}

// LOAD STORED ALERTS
async function loadAlerts() {
    const tbody = document.getElementById("alerts-table-body");
    tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4">Loading stored alert records...</td></tr>`;

    try {
        const res = await fetch("/api/v1/alerts");
        if (!res.ok) return;
        const data = await res.json();
        const alerts = data.alerts || [];

        if (alerts.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4">No alert records stored in SQLite database yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = "";
        alerts.forEach(item => {
            const tr = document.createElement("tr");
            const dateStr = item.created_at ? new Date(item.created_at).toLocaleString() : "-";
            const lvl = (item.risk_level || "low").toLowerCase();
            const evStr = (item.evidence || []).slice(0, 3).join(", ");
            const shortId = item.alert_id ? item.alert_id.substring(0, 8) + '...' : '-';

            tr.innerHTML = `
                <td><code>${shortId}</code></td>
                <td>${dateStr}</td>
                <td><span class="tag-chip">${item.detector_type || 'multi'}</span></td>
                <td><span class="badge ${lvl}">${lvl}</span></td>
                <td><strong>${item.risk_score ? item.risk_score.toFixed(2) : '0.00'}</strong></td>
                <td><small>${evStr || 'none'}</small></td>
                <td><small>${item.advisor_backend || 'template'}</small></td>
                <td>
                    <button class="btn-danger-sm" onclick="deleteAlert('${item.alert_id}')">Delete</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center py-4 text-danger">Failed to load alerts: ${err.message}</td></tr>`;
    }
}

async function deleteAlert(id) {
    if (!confirm("Are you sure you want to delete this local alert record?")) return;
    try {
        const res = await fetch(`/api/v1/alerts/${id}`, { method: "DELETE" });
        if (res.ok) loadAlerts();
    } catch (e) {
        alert("Failed to delete alert record.");
    }
}

// LOAD METRICS & MODELS
async function loadMetrics() {
    const modelsDiv = document.getElementById("models-status-list");
    const metricsGrid = document.getElementById("metrics-grid");

    modelsDiv.innerHTML = "Loading models metadata...";
    metricsGrid.innerHTML = "Loading metrics...";

    try {
        const infoRes = await fetch("/api/v1/info");
        if (infoRes.ok) {
            const infoData = await infoRes.json();
            const models = infoData.models || {};
            modelsDiv.innerHTML = "";

            Object.keys(models).forEach(name => {
                const item = models[name];
                const card = document.createElement("div");
                card.className = "model-card-item";
                card.innerHTML = `
                    <div class="header">
                        <span>${name.toUpperCase()} MODEL</span>
                        <span class="badge ${item.status === 'trained' ? 'low' : 'medium'}">${item.status}</span>
                    </div>
                    <div style="font-size: 0.78rem; color: var(--text-secondary);">
                        Version: <code>${item.model_version || 'fallback'}</code><br/>
                        File: <code>${item.dataset_name || name + '_model.joblib'}</code><br/>
                        Checksum: <code>${item.sha256 ? item.sha256.substring(0, 16) + '...' : 'none'}</code>
                    </div>
                `;
                modelsDiv.appendChild(card);
            });
        }

        const metricsRes = await fetch("/api/v1/metrics");
        if (metricsRes.ok) {
            const mData = await metricsRes.json();
            metricsGrid.innerHTML = `
                <div class="metric-box">
                    <div class="val">${mData.counters ? mData.counters.requests || 0 : 0}</div>
                    <div class="lbl">Total API Requests</div>
                </div>
                <div class="metric-box">
                    <div class="val" style="color: var(--risk-critical)">${mData.counters ? mData.counters.errors || 0 : 0}</div>
                    <div class="lbl">Total Errors</div>
                </div>
            `;
        }
    } catch (e) {
        modelsDiv.innerHTML = "Error loading model status.";
        metricsGrid.innerHTML = "Error loading metrics.";
    }
}
