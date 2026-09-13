/**
 * AutoMail AI Dashboard Controller
 * Handles SPA navigation, real-time data sync, email reading,
 * human-in-the-loop approval actions, rule management, and settings.
 */

// Security: Global Anti-CSRF header injector for mutating requests
const _origFetch = window.fetch;
window.fetch = function(url, options = {}) {
  options.headers = options.headers || {};
  if (options.method && options.method !== "GET") {
    if (typeof options.headers.set === "function") {
      options.headers.set("X-Requested-With", "AutoMail");
    } else {
      options.headers["X-Requested-With"] = "AutoMail";
    }
  }
  return _origFetch(url, options);
};

let currentView = "overview";
let currentCategory = "All";
let selectedEmailId = null;
let refreshInterval = null;

// DOM Ready
document.addEventListener("DOMContentLoaded", () => {
  initNav();
  initModals();
  initActions();
  loadAllData();

  // Auto-refresh interval (every 12 seconds)
  refreshInterval = setInterval(() => {
    loadAllData(false);
  }, 12000);
});

// Navigation Handling
function initNav() {
  document.querySelectorAll(".nav-item").forEach(item => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      const view = item.getAttribute("data-view");
      switchView(view);
    });
  });
}

function switchView(viewName) {
  currentView = viewName;

  // Update Nav Items
  document.querySelectorAll(".nav-item").forEach(item => {
    item.classList.toggle("active", item.getAttribute("data-view") === viewName);
  });

  // Update Views
  document.querySelectorAll(".view-section").forEach(sec => {
    sec.classList.toggle("active", sec.id === `view-${viewName}`);
  });

  // Update Title
  const titles = {
    overview: "Overview Dashboard",
    inbox: "Inbox & Email Threads",
    approvals: "Approval Queue (Human-in-the-Loop)",
    rules: "Automation Rules Engine",
    sent: "Sent History & Outbox",
    logs: "Live Activity Logs",
    settings: "Configuration & Credentials"
  };
  const titleEl = document.getElementById("current-view-title");
  if (titleEl) titleEl.textContent = titles[viewName] || "Dashboard";

  // Trigger view-specific refreshes
  if (viewName === "inbox") loadInbox();
  if (viewName === "approvals") loadApprovals();
  if (viewName === "rules") loadRules();
  if (viewName === "sent") loadSent();
  if (viewName === "logs") loadLogs();
  if (viewName === "settings") loadSettings();
}

// Global Actions & Buttons
function initActions() {
  // Sync button
  const syncBtn = document.getElementById("btn-sync-now");
  if (syncBtn) {
    syncBtn.addEventListener("click", triggerSync);
  }

  // Simulate Email Modal
  const simModalBtn = document.getElementById("btn-simulate-modal");
  if (simModalBtn) {
    simModalBtn.addEventListener("click", () => openModal("modal-simulate"));
  }

  // Run Simulation
  const runSimBtn = document.getElementById("btn-run-simulation");
  if (runSimBtn) {
    runSimBtn.addEventListener("click", runSimulation);
  }

  // Refresh Approvals
  const refreshApprBtn = document.getElementById("btn-refresh-approvals");
  if (refreshApprBtn) {
    refreshApprBtn.addEventListener("click", () => {
      loadApprovals();
      showToast("Refreshed approval queue", "info");
    });
  }

  // Refresh Logs
  const refreshLogsBtn = document.getElementById("btn-refresh-logs");
  if (refreshLogsBtn) {
    refreshLogsBtn.addEventListener("click", () => {
      loadLogs();
      showToast("Refreshed activity feed", "info");
    });
  }

  // New Rule Modal
  const newRuleModalBtn = document.getElementById("btn-new-rule-modal");
  if (newRuleModalBtn) {
    newRuleModalBtn.addEventListener("click", () => openModal("modal-rule"));
  }

  // Save New Rule
  const saveNewRuleBtn = document.getElementById("btn-save-new-rule");
  if (saveNewRuleBtn) {
    saveNewRuleBtn.addEventListener("click", saveNewRule);
  }

  // Test Connection
  const testConnBtn = document.getElementById("btn-test-connection");
  if (testConnBtn) {
    testConnBtn.addEventListener("click", testConnection);
  }

  // Save Settings
  const saveSettingsBtn = document.getElementById("btn-save-settings");
  if (saveSettingsBtn) {
    saveSettingsBtn.addEventListener("click", saveSettings);
  }

  // Inbox Category Pills
  document.querySelectorAll(".pill-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".pill-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");
      currentCategory = btn.getAttribute("data-cat") || "All";
      loadInbox();
    });
  });

  // Inbox Search
  const searchInput = document.getElementById("inbox-search");
  if (searchInput) {
    searchInput.addEventListener("input", () => loadInbox());
  }
}

// Modal handling
function initModals() {
  window.openModal = function(modalId) {
    const el = document.getElementById(modalId);
    if (el) el.classList.add("open");
  };
  window.closeModal = function(modalId) {
    const el = document.getElementById(modalId);
    if (el) el.classList.remove("open");
  };
}

// Toast Notifications
function showToast(msg, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span>${type === "success" ? "✓" : type === "error" ? "✕" : "ℹ"}</span><span>${msg}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(10px)";
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// Data Loaders
async function loadAllData(showToasts = true) {
  await loadStats();
  if (currentView === "overview") loadOverview();
  else if (currentView === "inbox") loadInbox();
  else if (currentView === "approvals") loadApprovals();
  else if (currentView === "rules") loadRules();
  else if (currentView === "sent") loadSent();
  else if (currentView === "logs") loadLogs();
}

async function loadStats() {
  try {
    const res = await fetch("/api/stats");
    if (!res.ok) return;
    const stats = await res.json();

    document.getElementById("stat-total-emails").textContent = stats.total_emails || 0;
    document.getElementById("stat-unread-emails").textContent = `${stats.unread_emails || 0} unread`;
    document.getElementById("stat-pending-approvals").textContent = stats.pending_approvals || 0;
    document.getElementById("stat-sent-count").textContent = stats.sent_count || 0;
    document.getElementById("stat-active-rules").textContent = stats.active_rules || 0;

    // Badges
    const badgeInbox = document.getElementById("badge-inbox-count");
    if (badgeInbox) badgeInbox.textContent = stats.unread_emails || 0;

    const badgeApprovals = document.getElementById("badge-approvals-count");
    if (badgeApprovals) {
      badgeApprovals.textContent = stats.pending_approvals || 0;
      badgeApprovals.style.display = stats.pending_approvals > 0 ? "inline-block" : "none";
    }

    const badgeRules = document.getElementById("badge-rules-count");
    if (badgeRules) badgeRules.textContent = stats.active_rules || 0;

  } catch (e) {
    console.error("Error loading stats:", e);
  }
}

// 1. OVERVIEW VIEW
async function loadOverview() {
  try {
    // Load top 3 pending approvals
    const resAppr = await fetch("/api/approvals?status=pending");
    const approvals = await resAppr.json();
    const container = document.getElementById("overview-pending-list");
    if (container) {
      if (approvals.length === 0) {
        container.innerHTML = `
          <div style="padding: 24px; text-align: center; color: var(--text-dim);">
            <p>✓ All caught up! No pending drafts require your review right now.</p>
          </div>
        `;
      } else {
        container.innerHTML = approvals.slice(0, 3).map(appr => `
          <div style="background: var(--bg-surface-elevated); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 14px; display: flex; justify-content: space-between; align-items: center;">
            <div style="max-width: 70%;">
              <div style="font-weight: 600; font-size: 0.88rem; color: #fff; margin-bottom: 2px;">${escapeHtml(appr.subject)}</div>
              <div style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(appr.recipient)}</div>
            </div>
            <button class="btn btn-primary btn-sm" onclick="switchView('approvals')">Review & Send</button>
          </div>
        `).join("");
      }
    }

    // Load top 5 logs
    const resLogs = await fetch("/api/logs?limit=5");
    const logs = await resLogs.json();
    const logsContainer = document.getElementById("overview-logs-list");
    if (logsContainer) {
      logsContainer.innerHTML = logs.map(l => `
        <div style="display: flex; gap: 8px; align-items: center;">
          <span style="color: var(--text-dim); font-size: 0.74rem;">${escapeHtml(l.timestamp.split(" ")[1] || l.timestamp)}</span>
          <span class="badge ${l.level === 'SUCCESS' ? 'badge-success' : l.level === 'ERROR' ? 'badge-urgent' : 'badge-category'}" style="font-size: 0.65rem;">${escapeHtml(l.category)}</span>
          <span style="color: var(--text-main); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(l.message)}</span>
        </div>
      `).join("");
    }
  } catch (e) {
    console.error("Error loading overview:", e);
  }
}

// 2. INBOX VIEW
async function loadInbox() {
  try {
    let url = "/api/emails";
    if (currentCategory && currentCategory !== "All") {
      url += `?category=${encodeURIComponent(currentCategory)}`;
    }
    const res = await fetch(url);
    const emails = await res.json();

    const searchQuery = (document.getElementById("inbox-search")?.value || "").toLowerCase();
    const filtered = emails.filter(e => {
      if (!searchQuery) return true;
      return (
        (e.subject || "").toLowerCase().includes(searchQuery) ||
        (e.from || "").toLowerCase().includes(searchQuery) ||
        (e.body || "").toLowerCase().includes(searchQuery)
      );
    });

    const container = document.getElementById("inbox-items-container");
    if (!container) return;

    if (filtered.length === 0) {
      container.innerHTML = `
        <div style="padding: 30px; text-align: center; color: var(--text-dim); font-size: 0.85rem;">
          No emails found in this filter.
        </div>
      `;
      return;
    }

    container.innerHTML = filtered.map(item => {
      const isSelected = item.id === selectedEmailId;
      const priorityClass = item.priority === "Urgent" ? "badge-urgent" : item.priority === "High" ? "badge-high" : item.priority === "Medium" ? "badge-medium" : "badge-low";
      return `
        <div class="email-card-item ${isSelected ? 'selected' : ''}" onclick="selectEmail('${item.id}')">
          <div class="email-item-header">
            <span class="email-sender">${escapeHtml(item.from)}</span>
            <span class="email-date">${escapeHtml((item.date || '').substring(0, 16))}</span>
          </div>
          <div class="email-subject">${escapeHtml(item.subject)}</div>
          <div class="email-snippet">${escapeHtml(item.snippet || item.body || '')}</div>
          <div class="email-badges">
            <span class="badge ${priorityClass}">${escapeHtml(item.priority || 'Normal')}</span>
            <span class="badge badge-category">${escapeHtml(item.category || 'General')}</span>
          </div>
        </div>
      `;
    }).join("");

    // Automatically select first email if none selected
    if (!selectedEmailId && filtered.length > 0) {
      selectEmail(filtered[0].id);
    }
  } catch (e) {
    console.error("Error loading inbox:", e);
  }
}

async function selectEmail(id) {
  selectedEmailId = id;
  loadInbox(); // refresh selection highlight

  try {
    const res = await fetch(`/api/emails/${id}`);
    if (!res.ok) return;
    const data = await res.json();
    const email = data.email;
    const draft = data.draft;

    const placeholder = document.getElementById("viewer-placeholder");
    const content = document.getElementById("viewer-content");
    if (placeholder) placeholder.style.display = "none";
    if (content) content.style.display = "block";

    const priorityClass = email.priority === "Urgent" ? "badge-urgent" : email.priority === "High" ? "badge-high" : "badge-medium";

    content.innerHTML = `
      <div class="viewer-header">
        <div class="viewer-title">${escapeHtml(email.subject)}</div>
        <div class="viewer-meta">
          <div><strong>From:</strong> ${escapeHtml(email.from)}</div>
          <div>${escapeHtml(email.date)}</div>
        </div>
      </div>

      <!-- AI Intel Box -->
      <div class="ai-intel-box">
        <div class="ai-intel-title">
          <span>🧠 AI Intelligence Breakdown</span>
          <span class="badge ${priorityClass}">${escapeHtml(email.priority)}</span>
          <span class="badge badge-category">${escapeHtml(email.category)}</span>
          <span class="badge" style="background: rgba(255,255,255,0.08); color: var(--text-main);">Sentiment: ${escapeHtml(email.sentiment)}</span>
        </div>
        <div class="ai-intel-summary">
          "${escapeHtml(email.summary || 'Summary unavailable')}"
        </div>
      </div>

      <!-- Email Body -->
      <div class="viewer-body">${escapeHtml(email.body)}</div>

      <!-- Linked Draft Banner if exists -->
      ${draft ? `
        <div style="margin-top: 20px; background: rgba(99, 102, 241, 0.1); border: 1px solid var(--border-active); border-radius: var(--radius-md); padding: 18px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
            <span style="font-weight: 600; font-size: 0.9rem; color: #fff;">✨ AI Generated Draft (${escapeHtml(draft.tone || 'Professional')})</span>
            <span class="badge ${draft.status === 'sent' ? 'badge-success' : 'badge-high'}">${escapeHtml(draft.status.toUpperCase())}</span>
          </div>
          <div style="font-size: 0.85rem; color: #cbd5e1; white-space: pre-wrap; line-height: 1.6; margin-bottom: 14px;">${escapeHtml(draft.body)}</div>
          ${draft.status === 'pending' ? `
            <div style="display: flex; gap: 10px;">
              <button class="btn btn-success btn-sm" onclick="approveDraft('${draft.id}')">✓ Approve & Send Now</button>
              <button class="btn btn-secondary btn-sm" onclick="switchView('approvals')">Open in Approval Queue</button>
            </div>
          ` : ''}
        </div>
      ` : ''}
    `;

    // Mark as read
    if (email.status === "unread") {
      await fetch(`/api/emails/${id}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "read" })
      });
      loadStats();
    }

  } catch (e) {
    console.error("Error loading email detail:", e);
  }
}

// 3. APPROVAL QUEUE VIEW
async function loadApprovals() {
  try {
    const res = await fetch("/api/approvals?status=pending");
    const drafts = await res.json();
    const container = document.getElementById("approval-queue-container");
    if (!container) return;

    if (drafts.length === 0) {
      container.innerHTML = `
        <div class="card" style="text-align: center; padding: 48px 24px; color: var(--text-dim);">
          <div style="font-size: 2.5rem; margin-bottom: 12px;">🎉</div>
          <h3 style="color: #fff; font-size: 1.15rem; margin-bottom: 8px;">Approval Queue is Clear!</h3>
          <p style="font-size: 0.88rem; max-width: 480px; margin: 0 auto;">All AI drafts have been reviewed or sent. When new emails arrive, automated replies will appear here for your one-click sign-off.</p>
        </div>
      `;
      return;
    }

    container.innerHTML = drafts.map(draft => {
      const orig = draft.original_email || {};
      return `
        <div class="approval-card" id="approval-card-${draft.id}">
          <div class="approval-header">
            <div class="approval-info">
              <h3>${escapeHtml(draft.subject)}</h3>
              <div style="font-size: 0.82rem; color: var(--text-muted);">
                Recipient: <strong style="color: #fff;">${escapeHtml(draft.recipient)}</strong>
              </div>
            </div>
            <div style="display: flex; gap: 8px; align-items: center;">
              <span class="badge badge-urgent">Needs Review</span>
            </div>
          </div>

          <div class="approval-columns">
            <!-- Original Email Column -->
            <div class="col-original">
              <div class="col-label">
                <span>Incoming Email</span>
                <span class="badge badge-category">${escapeHtml(orig.category || 'Inquiry')}</span>
              </div>
              <div style="font-size: 0.85rem; color: var(--text-muted); line-height: 1.6; white-space: pre-wrap; max-height: 220px; overflow-y: auto;">
                ${escapeHtml(orig.body || 'Original content not available')}
              </div>
            </div>

            <!-- Proposed AI Reply Column -->
            <div class="col-reply">
              <div class="col-label">
                <span>AI Proposed Response (Editable)</span>
                <span style="color: var(--accent-secondary); font-size: 0.72rem;">✨ AI Generated</span>
              </div>
              <textarea class="draft-textarea" id="draft-text-${draft.id}">${escapeHtml(draft.body)}</textarea>
            </div>
          </div>

          <!-- Bottom Action Bar -->
          <div class="approval-actions">
            <div class="tone-selector">
              <span>Regenerate Tone:</span>
              <select class="tone-select" id="tone-select-${draft.id}">
                <option value="Professional" ${draft.tone === 'Professional' ? 'selected' : ''}>Professional</option>
                <option value="Friendly" ${draft.tone === 'Friendly' ? 'selected' : ''}>Friendly</option>
                <option value="Direct" ${draft.tone === 'Direct' ? 'selected' : ''}>Direct & Concise</option>
                <option value="Executive" ${draft.tone === 'Executive' ? 'selected' : ''}>Executive</option>
              </select>
              <button class="btn btn-secondary btn-sm" onclick="regenerateDraft('${draft.id}')">✨ Regenerate</button>
            </div>

            <div style="display: flex; gap: 10px;">
              <button class="btn btn-danger btn-sm" onclick="rejectDraft('${draft.id}')">Dismiss / Reject</button>
              <button class="btn btn-success" onclick="approveDraft('${draft.id}')">
                <svg fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/></svg>
                <span>Approve & Send Email</span>
              </button>
            </div>
          </div>
        </div>
      `;
    }).join("");
  } catch (e) {
    console.error("Error loading approvals:", e);
  }
}

async function approveDraft(draftId) {
  const card = document.getElementById(`approval-card-${draftId}`);
  const textarea = document.getElementById(`draft-text-${draftId}`);
  const updatedBody = textarea ? textarea.value : null;

  try {
    // If text was edited in textarea, update draft first
    if (updatedBody) {
      await fetch(`/api/approvals/${draftId}/update`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ body: updatedBody })
      });
    }

    const res = await fetch(`/api/approvals/${draftId}/approve`, { method: "POST" });
    const data = await res.json();

    if (res.ok && data.success) {
      showToast(data.message || "Email approved and sent successfully!", "success");
      loadStats();
      loadApprovals();
      if (currentView === "overview") loadOverview();
    } else {
      showToast(data.detail || "Failed to dispatch email", "error");
    }
  } catch (e) {
    showToast("Error approving draft: " + e.message, "error");
  }
}

async function rejectDraft(draftId) {
  if (!confirm("Are you sure you want to dismiss this AI draft?")) return;
  try {
    const res = await fetch(`/api/approvals/${draftId}/reject`, { method: "POST" });
    if (res.ok) {
      showToast("Draft dismissed", "info");
      loadStats();
      loadApprovals();
    }
  } catch (e) {
    showToast("Error dismissing draft: " + e.message, "error");
  }
}

async function regenerateDraft(draftId) {
  const toneSelect = document.getElementById(`tone-select-${draftId}`);
  const tone = toneSelect ? toneSelect.value : "Professional";
  const textarea = document.getElementById(`draft-text-${draftId}`);

  try {
    if (textarea) textarea.value = "Regenerating response with AI...";
    const res = await fetch(`/api/approvals/${draftId}/regenerate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tone: tone })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      if (textarea) textarea.value = data.body;
      showToast(`Regenerated draft in ${tone} tone`, "success");
    } else {
      showToast("Regeneration failed", "error");
    }
  } catch (e) {
    showToast("Error regenerating draft: " + e.message, "error");
  }
}

// 4. RULES VIEW
async function loadRules() {
  try {
    const res = await fetch("/api/rules");
    const rules = await res.json();
    const container = document.getElementById("rules-grid-container");
    if (!container) return;

    container.innerHTML = rules.map(rule => `
      <div class="rule-card">
        <div class="rule-top">
          <div class="rule-name">${escapeHtml(rule.name)}</div>
          <label class="switch">
            <input type="checkbox" ${rule.enabled ? 'checked' : ''} onchange="toggleRule('${rule.id}', this.checked)">
            <span class="slider"></span>
          </label>
        </div>

        <div class="rule-condition-box">
          IF <span class="rule-tag">${escapeHtml(rule.condition_field)}</span>
          ${escapeHtml(rule.condition_operator)}
          "<strong style="color: #fff;">${escapeHtml(rule.condition_value)}</strong>"
        </div>

        <div style="font-size: 0.82rem; color: var(--text-muted);">
          THEN: <span class="badge badge-category">${escapeHtml(rule.action)}</span>
          ${rule.action_param ? `<span style="color: #fff; font-size: 0.78rem;">(${escapeHtml(rule.action_param)})</span>` : ''}
        </div>

        <div style="display: flex; justify-content: flex-end; margin-top: auto;">
          <button class="btn btn-danger btn-sm" onclick="deleteRule('${rule.id}')">Delete Rule</button>
        </div>
      </div>
    `).join("");
  } catch (e) {
    console.error("Error loading rules:", e);
  }
}

async function toggleRule(ruleId, enabled) {
  try {
    await fetch(`/api/rules/${ruleId}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: enabled })
    });
    showToast(`Rule ${enabled ? 'enabled' : 'disabled'}`, "info");
    loadStats();
  } catch (e) {
    showToast("Failed to update rule state", "error");
  }
}

async function deleteRule(ruleId) {
  if (!confirm("Are you sure you want to delete this rule?")) return;
  try {
    const res = await fetch(`/api/rules/${ruleId}`, { method: "DELETE" });
    if (res.ok) {
      showToast("Rule deleted", "info");
      loadRules();
      loadStats();
    }
  } catch (e) {
    showToast("Failed to delete rule", "error");
  }
}

async function saveNewRule() {
  const name = document.getElementById("new-rule-name")?.value.trim();
  const field = document.getElementById("new-rule-field")?.value;
  const op = document.getElementById("new-rule-op")?.value;
  const val = document.getElementById("new-rule-val")?.value.trim();
  const action = document.getElementById("new-rule-action")?.value;
  const param = document.getElementById("new-rule-param")?.value.trim();

  if (!name || !val) {
    showToast("Please enter a rule name and match value.", "error");
    return;
  }

  try {
    const res = await fetch("/api/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: name,
        condition_field: field,
        condition_operator: op,
        condition_value: val,
        action: action,
        action_param: param,
        enabled: true
      })
    });
    if (res.ok) {
      showToast("New automation rule created!", "success");
      closeModal("modal-rule");
      loadRules();
      loadStats();
    }
  } catch (e) {
    showToast("Error creating rule: " + e.message, "error");
  }
}

// 5. SENT HISTORY VIEW
async function loadSent() {
  try {
    const res = await fetch("/api/sent");
    const sentList = await res.json();
    const tbody = document.getElementById("sent-table-body");
    if (!tbody) return;

    if (sentList.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 30px;">No sent emails recorded yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = sentList.map(item => `
      <tr>
        <td style="font-weight: 500; color: #fff;">${escapeHtml(item.to)}</td>
        <td>${escapeHtml(item.subject)}</td>
        <td style="color: var(--text-dim);">${escapeHtml(item.sent_at)}</td>
        <td><span style="font-size: 0.78rem; color: var(--accent-secondary);">${escapeHtml(item.method || 'SMTP')}</span></td>
        <td><span class="badge badge-success">${escapeHtml(item.status || 'Delivered')}</span></td>
      </tr>
    `).join("");
  } catch (e) {
    console.error("Error loading sent:", e);
  }
}

// 6. LIVE LOGS VIEW
async function loadLogs() {
  try {
    const res = await fetch("/api/logs?limit=100");
    const logs = await res.json();
    const terminal = document.getElementById("logs-terminal-view");
    if (!terminal) return;

    terminal.innerHTML = logs.map(l => `
      <div class="log-line">
        <span class="log-time">[${escapeHtml(l.timestamp)}]</span>
        <span class="log-cat">[${escapeHtml(l.category)}]</span>
        <span class="log-level-${escapeHtml(l.level)}">[${escapeHtml(l.level)}]</span>
        <span style="color: #e2e8f0;">${escapeHtml(l.message)}</span>
      </div>
    `).join("");
  } catch (e) {
    console.error("Error loading logs:", e);
  }
}

// 7. SETTINGS VIEW
async function loadSettings() {
  try {
    const res = await fetch("/api/settings");
    const cfg = await res.json();

    const acc = cfg.account || {};
    const ai = cfg.ai || {};
    const auto = cfg.automation || {};

    document.getElementById("setting-email").value = acc.email_address || "";
    document.getElementById("setting-password").value = "";
    document.getElementById("setting-password").placeholder = acc.has_password ? "•••••••••••••••• (Encrypted on Disk)" : "Enter 16-character App Password";

    document.getElementById("setting-imap").value = acc.imap_server || "imap.gmail.com";
    document.getElementById("setting-imap-port").value = acc.imap_port || 993;
    document.getElementById("setting-smtp").value = acc.smtp_server || "smtp.gmail.com";
    document.getElementById("setting-smtp-port").value = acc.smtp_port || 587;

    document.getElementById("setting-ai-provider").value = ai.provider || "gemini";
    document.getElementById("setting-gemini-key").value = "";
    document.getElementById("setting-gemini-key").placeholder = ai.has_api_key ? (ai.gemini_api_key_masked + " (Encrypted)") : "AIzaSy... (Optional)";
    document.getElementById("setting-gemini-model").value = ai.model_name || "gemini-1.5-flash";

    document.getElementById("setting-auto-mode").value = auto.mode || "review_required";
    document.getElementById("setting-sync-interval").value = auto.sync_interval_seconds || 60;
  } catch (e) {
    console.error("Error loading settings:", e);
  }
}

async function saveSettings() {
  const emailAddr = document.getElementById("setting-email").value.trim();
  const password = document.getElementById("setting-password").value.trim();
  const imapServer = document.getElementById("setting-imap").value.trim();
  const imapPort = parseInt(document.getElementById("setting-imap-port").value) || 993;
  const smtpServer = document.getElementById("setting-smtp").value.trim();
  const smtpPort = parseInt(document.getElementById("setting-smtp-port").value) || 587;

  const aiProvider = document.getElementById("setting-ai-provider").value;
  const geminiKey = document.getElementById("setting-gemini-key").value.trim();
  const geminiModel = document.getElementById("setting-gemini-model").value;

  const autoMode = document.getElementById("setting-auto-mode").value;
  const interval = parseInt(document.getElementById("setting-sync-interval").value) || 60;

  const payload = {
    account: {
      email_address: emailAddr,
      app_password: password,
      imap_server: imapServer,
      imap_port: imapPort,
      smtp_server: smtpServer,
      smtp_port: smtpPort,
      connection_type: "app_password"
    },
    ai: {
      provider: aiProvider,
      gemini_api_key: geminiKey,
      model_name: geminiModel,
      default_tone: "Professional"
    },
    automation: {
      mode: autoMode,
      auto_sync: true,
      sync_interval_seconds: interval,
      notify_urgent: true,
      auto_categorize: true,
      auto_draft: true
    }
  };

  try {
    const res = await fetch("/api/settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      showToast("Settings saved successfully!", "success");
      loadSettings();
    }
  } catch (e) {
    showToast("Failed to save settings: " + e.message, "error");
  }
}

async function testConnection() {
  const resultDiv = document.getElementById("test-connection-result");
  if (resultDiv) {
    resultDiv.style.display = "block";
    resultDiv.style.color = "var(--accent-secondary)";
    resultDiv.textContent = "Testing IMAP & SMTP connection diagnostics...";
  }

  try {
    const res = await fetch("/api/settings/test-connection", { method: "POST" });
    const data = await res.json();
    if (resultDiv) {
      resultDiv.style.color = data.success ? "var(--accent-emerald)" : "var(--accent-rose)";
      resultDiv.textContent = (data.success ? "✓ " : "✕ ") + data.message;
    }
  } catch (e) {
    if (resultDiv) {
      resultDiv.style.color = "var(--accent-rose)";
      resultDiv.textContent = "Connection check failed: " + e.message;
    }
  }
}

// Sync & Simulation triggers
async function triggerSync() {
  const icon = document.getElementById("sync-icon");
  const text = document.getElementById("sync-btn-text");
  if (icon) icon.classList.add("spin");
  if (text) text.textContent = "Syncing...";

  try {
    const res = await fetch("/api/emails/sync", { method: "POST" });
    const data = await res.json();
    if (data.status === "success") {
      showToast(`Sync complete! Fetched ${data.count} new emails.`, "success");
    } else {
      showToast(data.message || "Sync checked.", "info");
    }
    loadAllData(false);
  } catch (e) {
    showToast("Sync error: " + e.message, "error");
  } finally {
    if (icon) icon.classList.remove("spin");
    if (text) text.textContent = "Sync Emails";
  }
}

async function runSimulation() {
  const scenario = document.getElementById("simulate-scenario-select")?.value || "customer_support";
  try {
    const res = await fetch("/api/emails/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: scenario })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      closeModal("modal-simulate");
      showToast("Test email generated and processed by AI!", "success");
      loadAllData(false);
      switchView("approvals");
    }
  } catch (e) {
    showToast("Simulation error: " + e.message, "error");
  }
}

// Utility
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
