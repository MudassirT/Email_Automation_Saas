/**
 * AutoMail AI Dashboard Controller
 * Handles SPA navigation, real-time data sync, email reading,
 * human-in-the-loop approval actions, rule management, and settings.
 */

// Security: Global Anti-CSRF header injector for mutating requests
// Security: Global Anti-CSRF, Multi-Tenant Isolation, and JWT Auth token injector
const _origFetch = window.fetch;
window.fetch = function(url, options = {}) {
  options.headers = options.headers || {};
  const currentUserId = localStorage.getItem("automail_user_id") || "default";
  const token = localStorage.getItem("automail_token") || "";

  if (typeof options.headers.set === "function") {
    options.headers.set("X-User-Id", currentUserId);
    if (token) {
      options.headers.set("Authorization", `Bearer ${token}`);
    }
    if (options.method && options.method !== "GET") {
      options.headers.set("X-Requested-With", "AutoMail");
    }
  } else {
    options.headers["X-User-Id"] = currentUserId;
    if (token) {
      options.headers["Authorization"] = `Bearer ${token}`;
    }
    if (options.method && options.method !== "GET") {
      options.headers["X-Requested-With"] = "AutoMail";
    }
  }
  return _origFetch(url, options);
};

let currentView = "overview";
let currentCategory = "All";
let selectedEmailId = null;
let refreshInterval = null;
let currentUser = null;

// DOM Ready
document.addEventListener("DOMContentLoaded", async () => {
  // Check for Google OAuth callback parameters in URL
  const urlParams = new URLSearchParams(window.location.search);
  const redirectToken = urlParams.get("token");
  const redirectUserId = urlParams.get("user_id");
  const authError = urlParams.get("auth_error");

  if (redirectToken) {
    localStorage.setItem("automail_token", redirectToken);
    if (redirectUserId) localStorage.setItem("automail_user_id", redirectUserId);
    window.history.replaceState({}, document.title, window.location.pathname);
    showToast("Google sign-in successful! Welcome to your isolated workspace.", "success");
  } else if (authError) {
    window.history.replaceState({}, document.title, window.location.pathname);
    showToast(`Google login issue: ${authError}`, "error");
  }

  initTheme();
  initNav();
  initModals();
  initActions();
  initUserSwitcher();
  initProviderPresets();

  await checkAuthStatus();
  await loadAllData();

  // Auto-refresh interval (every 12 seconds)
  refreshInterval = setInterval(() => {
    loadAllData(false);
  }, 12000);
});

// Theme Management (Dark & Light)
function initTheme() {
  const saved = localStorage.getItem("automail_theme");
  const systemPrefersLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
  const initialTheme = saved || (systemPrefersLight ? "light" : "dark");
  applyTheme(initialTheme);

  const toggleBtn = document.getElementById("btn-theme-toggle");
  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      const next = current === "dark" ? "light" : "dark";
      applyTheme(next);
      showToast(`Switched to ${next === "light" ? "Light" : "Dark"} theme`, "info");
    });
  }
}

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("automail_theme", theme);
  const icon = document.getElementById("theme-icon");
  const text = document.getElementById("theme-text");
  if (icon && text) {
    if (theme === "light") {
      icon.textContent = "☀️";
      text.textContent = "Light";
    } else {
      icon.textContent = "🌙";
      text.textContent = "Dark";
    }
  }
}

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
    settings: "Configuration & Credentials",
    admin: "Enterprise Admin Monitoring Console"
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
  if (viewName === "admin") loadAdminView();
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

  // Test AI Connection & API Key
  const testAIBtn = document.getElementById("btn-test-ai");
  if (testAIBtn) {
    testAIBtn.addEventListener("click", testAIConnection);
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

  // Admin Monitoring Actions
  const adminRefreshBtn = document.getElementById("btn-admin-refresh");
  if (adminRefreshBtn) {
    adminRefreshBtn.addEventListener("click", () => {
      loadAdminView();
      showToast("Refreshed system telemetry", "info");
    });
  }

  const adminSyncAllBtn = document.getElementById("btn-admin-sync-all");
  if (adminSyncAllBtn) {
    adminSyncAllBtn.addEventListener("click", adminSyncAll);
  }

  const adminLogsBtn = document.getElementById("btn-admin-refresh-logs");
  if (adminLogsBtn) {
    adminLogsBtn.addEventListener("click", () => {
      loadAdminAuditLogs();
      showToast("Refreshed enterprise audit feed", "info");
    });
  }

  const adminUserSearch = document.getElementById("admin-user-search");
  if (adminUserSearch) {
    adminUserSearch.addEventListener("input", (e) => {
      renderAdminUsersTable(e.target.value.trim().toLowerCase());
    });
  }
}

// Modal handling
function initModals() {
  window.openModal = function(modalId) {
    const el = document.getElementById(modalId);
    if (el) {
      el.classList.add("open");
      if (modalId === "modal-switch-user") {
        renderTenantList();
      }
    }
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
  fetch("/api/settings").then(r => r.json()).then(cfg => updateAIStatusPill(cfg)).catch(()=>{});
  if (currentView === "overview") loadOverview();
  else if (currentView === "inbox") loadInbox();
  else if (currentView === "approvals") loadApprovals();
  else if (currentView === "rules") loadRules();
  else if (currentView === "sent") loadSent();
  else if (currentView === "logs") loadLogs();
  else if (currentView === "admin") loadAdminView();
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

function getInitials(name) {
  if (!name) return "EM";
  const clean = name.replace(/<[^>]+>/g, "").trim();
  const parts = clean.split(/\s+/);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return clean.slice(0, 2).toUpperCase() || "EM";
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
    const senderName = email.sender_name || (email.from ? email.from.split("<")[0].trim().replace(/['"]/g, "") : "Sender");
    const senderOrg = email.sender_organization || (email.from && email.from.includes("@") ? email.from.split("@")[1].split(".")[0].toUpperCase() : "External");
    const senderInitials = getInitials(senderName);
    const tasks = Array.isArray(email.tasks) && email.tasks.length > 0 ? email.tasks : ["Review inquiry & respond"];
    const aiActions = Array.isArray(email.ai_automated_actions) && email.ai_automated_actions.length > 0
      ? email.ai_automated_actions
      : ["Ingested & parsed by AI", "Intent analyzed", "Prepared contextual response"];
    const compressed = email.compressed_summary || email.summary || "Summary unavailable";

    content.innerHTML = `
      <!-- 1. AI EXECUTIVE BRIEFING FOR OWNER -->
      <div class="briefing-card">
        <div class="briefing-header">
          <div class="sender-profile">
            <div class="sender-avatar">${escapeHtml(senderInitials)}</div>
            <div>
              <div class="sender-name">${escapeHtml(senderName)}</div>
              <div class="sender-org">🏢 ${escapeHtml(senderOrg)} • <span style="font-family: monospace;">${escapeHtml(email.from)}</span></div>
            </div>
          </div>
          <div style="display: flex; gap: 8px; flex-wrap: wrap; align-items: center;">
            <span class="badge ${priorityClass}">${escapeHtml(email.priority || 'Normal')}</span>
            <span class="badge badge-category">${escapeHtml(email.category || 'General')}</span>
            <span class="badge" style="background: rgba(255,255,255,0.08); color: var(--text-main);">Sentiment: ${escapeHtml(email.sentiment || 'Neutral')}</span>
          </div>
        </div>

        <!-- IN PLAIN WORDS (COMPRESSED SUMMARY FOR OWNER) -->
        <div class="briefing-owner-callout">
          <div class="callout-title">
            <span>💬 WHAT THIS EMAIL SAYS (COMPRESSED FOR OWNER)</span>
            <span class="callout-intent">🎯 Goal: ${escapeHtml(email.core_intent || email.category || 'General')}</span>
          </div>
          <div class="callout-text">
            "${escapeHtml(compressed)}"
          </div>
        </div>

        <!-- EXTRACTED ACTIONABLE TASKS CHECKLIST -->
        <div class="task-checklist-box">
          <div class="task-checklist-title">
            <span>📋 Actionable Tasks Extracted by AI (${tasks.length})</span>
            <span style="font-size: 0.75rem; color: var(--text-dim);">Checked items ready for automated resolution</span>
          </div>
          <div class="task-items-list">
            ${tasks.map((t, idx) => `
              <label class="task-checklist-item">
                <input type="checkbox" checked id="task-chk-${email.id}-${idx}">
                <span>${escapeHtml(t)}</span>
              </label>
            `).join('')}
          </div>
        </div>

        <!-- AI AUTOMATED RESOLUTION & 1-CLICK DISPATCH -->
        <div class="ai-automated-section">
          <div class="ai-pill-row">
            <span style="font-size: 0.74rem; color: var(--text-muted); font-weight: 600;">AI Executed:</span>
            ${aiActions.map(act => `<span class="ai-pill-tag">✓ ${escapeHtml(act)}</span>`).join('')}
          </div>
          ${draft && draft.status === 'pending' ? `
            <div style="margin-top: 12px; display: flex; gap: 10px; align-items: center; justify-content: space-between; background: rgba(99, 102, 241, 0.08); padding: 12px 16px; border-radius: var(--radius-md); border: 1px dashed var(--border-active); flex-wrap: wrap;">
              <div>
                <div style="font-weight: 600; font-size: 0.88rem; color: #fff;">🤖 Ready for One-Click AI Task Automation</div>
                <div style="font-size: 0.76rem; color: var(--text-muted);">AI drafted response addressing all ${tasks.length} task(s).</div>
              </div>
              <button class="btn btn-primary btn-ai-execute" onclick="approveDraft('${draft.id}')">
                <span>🚀 Execute Tasks & Send AI Reply</span>
              </button>
            </div>
          ` : ''}
        </div>
      </div>

      <!-- 2. ORIGINAL EMAIL THREAD -->
      <div class="viewer-header">
        <div class="viewer-title">${escapeHtml(email.subject)}</div>
        <div class="viewer-meta">
          <div><strong>From:</strong> ${escapeHtml(email.from)}</div>
          <div>${escapeHtml(email.date)}</div>
        </div>
      </div>

      <!-- Full Email Body -->
      <div class="viewer-body">${escapeHtml(email.body)}</div>

      <!-- 3. AI GENERATED RESPONSE DRAFT (IF EXISTS) -->
      ${draft ? `
        <div style="margin-top: 24px; background: rgba(99, 102, 241, 0.08); border: 1px solid var(--border-active); border-radius: var(--radius-md); padding: 18px;">
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
      const senderName = orig.sender_name || (orig.from ? orig.from.split("<")[0].trim().replace(/['"]/g, "") : "Sender");
      const senderOrg = orig.sender_organization || (orig.from && orig.from.includes("@") ? orig.from.split("@")[1].split(".")[0].toUpperCase() : "External");
      const compressed = orig.compressed_summary || orig.summary || "Summary unavailable";
      const tasks = Array.isArray(orig.tasks) && orig.tasks.length > 0 ? orig.tasks : ["Respond to inquiry"];

      return `
        <div class="approval-card" id="approval-card-${draft.id}">
          <div class="approval-header">
            <div class="approval-info">
              <h3>${escapeHtml(draft.subject)}</h3>
              <div style="font-size: 0.82rem; color: var(--text-muted); margin-top: 4px;">
                Recipient: <strong style="color: #fff;">${escapeHtml(draft.recipient)}</strong> • 🏢 ${escapeHtml(senderOrg)}
              </div>
            </div>
            <div style="display: flex; gap: 8px; align-items: center;">
              <span class="badge badge-urgent">Needs Sign-off</span>
            </div>
          </div>

          <!-- Owner Quick Briefing Callout -->
          <div class="briefing-owner-callout" style="margin: 0 0 16px 0;">
            <div class="callout-title">
              <span>💬 IN PLAIN WORDS (WHAT ${escapeHtml(senderName.toUpperCase())} WANTS):</span>
              <span class="callout-intent">Goal: ${escapeHtml(orig.core_intent || orig.category || 'General')}</span>
            </div>
            <div class="callout-text" style="font-size: 0.9rem;">
              "${escapeHtml(compressed)}"
            </div>
            <div style="margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px;">
              ${tasks.map(t => `<span class="ai-pill-tag" style="background: rgba(99,102,241,0.12); color: var(--accent-secondary); border-color: var(--border-active);">📋 ${escapeHtml(t)}</span>`).join('')}
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
                <span style="color: var(--accent-secondary); font-size: 0.72rem;">✨ Addressed ${tasks.length} task(s)</span>
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

// --- PROVIDER PRESETS ---
const PROVIDER_PRESETS = {
  gmail: {
    name: "Google Gmail",
    imap: "imap.gmail.com",
    imap_port: 993,
    smtp: "smtp.gmail.com",
    smtp_port: 587,
    guideTitle: "Easy 3-Step Gmail Connection:",
    steps: [
      "Make sure <strong>2-Step Verification</strong> is ON in your Google Account &gt; Security.",
      'Visit <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noopener" style="color: var(--accent-primary); text-decoration: underline;">Google App Passwords</a> and generate a 16-letter password for <em>"AutoMail"</em>.',
      "Enter your email and paste the App Password below. It is encrypted on disk immediately."
    ]
  },
  outlook: {
    name: "Microsoft Outlook / Office 365",
    imap: "outlook.office365.com",
    imap_port: 993,
    smtp: "smtp.office365.com",
    smtp_port: 587,
    guideTitle: "Easy 3-Step Outlook / O365 Connection:",
    steps: [
      "Ensure IMAP access is enabled in your Outlook / Office 365 mailbox settings.",
      "If 2-Step Verification is active, generate an App Password in your Microsoft Account Security.",
      "Enter your Outlook email and password below. Encrypted with AES-256 Fernet keys."
    ]
  },
  yahoo: {
    name: "Yahoo Mail",
    imap: "imap.mail.yahoo.com",
    imap_port: 993,
    smtp: "smtp.mail.yahoo.com",
    smtp_port: 587,
    guideTitle: "Easy 3-Step Yahoo Mail Connection:",
    steps: [
      "Go to Yahoo Account Security &gt; Generate App Password.",
      'Create an App Password labeled <em>"AutoMail"</em> and copy it.',
      "Paste your Yahoo email and App Password below. End-to-end isolated."
    ]
  },
  custom: {
    name: "Custom Mail Server",
    imap: "",
    imap_port: 993,
    smtp: "",
    smtp_port: 587,
    guideTitle: "Custom IMAP / SMTP Connection:",
    steps: [
      "Enter your email provider's IMAP & SMTP host addresses and port numbers.",
      "Standard secure ports are Port 993 (SSL/TLS) for IMAP and Port 587 (STARTTLS) for SMTP.",
      "Input your credentials. All secrets are stored exclusively in your private tenant partition."
    ]
  }
};

function initProviderPresets() {
  document.querySelectorAll(".provider-preset-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const provider = btn.getAttribute("data-provider");
      if (provider) selectProviderPreset(provider, true);
    });
  });
}

function selectProviderPreset(providerKey, overwriteValues = true) {
  const preset = PROVIDER_PRESETS[providerKey] || PROVIDER_PRESETS.gmail;

  document.querySelectorAll(".provider-preset-btn").forEach(b => {
    b.classList.toggle("active", b.getAttribute("data-provider") === providerKey);
  });

  if (overwriteValues) {
    if (preset.imap) document.getElementById("setting-imap").value = preset.imap;
    document.getElementById("setting-imap-port").value = preset.imap_port;
    if (preset.smtp) document.getElementById("setting-smtp").value = preset.smtp;
    document.getElementById("setting-smtp-port").value = preset.smtp_port;
  }

  const titleEl = document.getElementById("guide-header-title");
  if (titleEl) titleEl.textContent = preset.guideTitle;

  const listEl = document.getElementById("guide-step-list");
  if (listEl && preset.steps) {
    listEl.innerHTML = preset.steps.map(s => `<li>${s}</li>`).join("");
  }
}

// --- USER / MULTI-TENANT WORKSPACE SWITCHER ---
async function initUserSwitcher() {
  const pill = document.getElementById("user-switcher-pill");
  if (pill) {
    pill.addEventListener("click", () => openModal("modal-switch-user"));
  }

  const confirmBtn = document.getElementById("btn-confirm-switch-user");
  if (confirmBtn) {
    confirmBtn.addEventListener("click", () => {
      const input = document.getElementById("input-new-user-id");
      const uid = input?.value.trim();
      if (!uid) {
        showToast("Please enter a User ID", "warning");
        return;
      }
      switchTenant(uid);
    });
  }

  updateActiveUserBadge();
}

function updateActiveUserBadge() {
  const currentUserId = localStorage.getItem("automail_user_id") || "default";
  const badge = document.getElementById("current-user-badge");
  if (badge) {
    badge.textContent = `User: ${currentUserId}`;
  }
}

async function renderTenantList() {
  const container = document.getElementById("tenant-list-container");
  if (!container) return;

  try {
    const res = await fetch("/api/auth/tenants");
    const tenants = await res.json();
    const activeUserId = localStorage.getItem("automail_user_id") || "default";

    container.innerHTML = tenants.map(t => {
      const isActive = t.id === activeUserId;
      return `
        <div class="tenant-card ${isActive ? 'active' : ''}" onclick="switchTenant('${escapeHtml(t.id)}')">
          <div class="tenant-card-info">
            <span style="font-size: 1.1rem;">${isActive ? '✅' : '🏢'}</span>
            <div>
              <div class="tenant-card-name">${escapeHtml(t.name || t.id)}</div>
              <div class="tenant-card-sub">User ID: ${escapeHtml(t.id)} ${isActive ? '• Active Workspace' : ''}</div>
            </div>
          </div>
          <button class="btn btn-sm ${isActive ? 'btn-success' : 'btn-secondary'}">
            ${isActive ? 'Active' : 'Switch'}
          </button>
        </div>
      `;
    }).join("");
  } catch (e) {
    container.innerHTML = `<div style="color: var(--text-dim); font-size: 0.8rem;">Failed to load accounts: ${escapeHtml(e.message)}</div>`;
  }
}

async function switchTenant(newUserId) {
  try {
    const res = await fetch("/api/auth/switch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: newUserId })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      const activeId = data.active_user_id;
      localStorage.setItem("automail_user_id", activeId);
      closeModal("modal-switch-user");
      updateActiveUserBadge();
      showToast(`Switched to workspace '${activeId}' (Zero Cross-Exposure)`, "success");
      
      // Clear selection and reload all data for new isolated workspace
      selectedEmailId = null;
      await loadAllData(false);
      await loadSettings();
    } else {
      showToast("Failed to switch workspace", "error");
    }
  } catch (e) {
    showToast("Switch workspace error: " + e.message, "error");
  }
}

// 7. SETTINGS VIEW
async function loadSettings() {
  try {
    const res = await fetch("/api/settings");
    const cfg = await res.json();

    updateAIStatusPill(cfg);

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

    // Detect and select corresponding provider preset
    const imapLower = (acc.imap_server || "").toLowerCase();
    if (imapLower.includes("gmail")) {
      selectProviderPreset("gmail", false);
    } else if (imapLower.includes("office365") || imapLower.includes("outlook")) {
      selectProviderPreset("outlook", false);
    } else if (imapLower.includes("yahoo")) {
      selectProviderPreset("yahoo", false);
    } else if (acc.imap_server) {
      selectProviderPreset("custom", false);
    } else {
      selectProviderPreset("gmail", false);
    }

    document.getElementById("setting-ai-provider").value = ai.provider || "gemini";
    document.getElementById("setting-gemini-key").value = "";
    document.getElementById("setting-gemini-key").placeholder = ai.has_api_key ? (ai.gemini_api_key_masked + " (Encrypted)") : "AIzaSy... (Enter to activate Gemini)";
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

async function testAIConnection() {
  const resultDiv = document.getElementById("test-ai-result");
  const btn = document.getElementById("btn-test-ai");
  if (resultDiv) {
    resultDiv.style.display = "block";
    resultDiv.style.color = "var(--accent-secondary)";
    resultDiv.textContent = "Verifying AI connectivity and API key...";
  }
  if (btn) btn.disabled = true;

  try {
    const res = await fetch("/api/settings/test-ai", { method: "POST" });
    const data = await res.json();
    if (resultDiv) {
      resultDiv.style.color = data.success ? "var(--accent-emerald)" : "var(--accent-rose)";
      resultDiv.textContent = (data.success ? "✓ " : "✕ ") + data.message;
    }
    showToast(data.message, data.success ? "success" : "error");
    const dot = document.getElementById("ai-status-dot");
    const label = document.getElementById("ai-status-label");
    if (dot && label && data.success) {
      dot.style.backgroundColor = "var(--accent-emerald)";
      dot.style.boxShadow = "0 0 8px var(--accent-emerald)";
      label.textContent = "AI: Online & Verified";
    }
  } catch (e) {
    if (resultDiv) {
      resultDiv.style.color = "var(--accent-rose)";
      resultDiv.textContent = "AI verification error: " + e.message;
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

function updateAIStatusPill(cfg) {
  const dot = document.getElementById("ai-status-dot");
  const label = document.getElementById("ai-status-label");
  if (!dot || !label) return;

  const ai = cfg?.ai || {};
  if (ai.provider === "gemini") {
    if (ai.has_api_key) {
      dot.style.backgroundColor = "var(--accent-emerald)";
      dot.style.boxShadow = "0 0 8px var(--accent-emerald)";
      label.textContent = `AI: Gemini (${ai.model_name || 'Flash'}) Active`;
    } else {
      dot.style.backgroundColor = "var(--accent-amber)";
      dot.style.boxShadow = "0 0 8px var(--accent-amber)";
      label.textContent = "AI: Gemini (Key Needed)";
    }
  } else {
    dot.style.backgroundColor = "var(--accent-secondary)";
    dot.style.boxShadow = "0 0 8px var(--accent-secondary)";
    label.textContent = "AI: Smart Built-in Engine";
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

// ==========================================
// 8. ENTERPRISE ADMIN MONITORING VIEW
// ==========================================
let _cachedAdminUsers = [];

async function loadAdminView() {
  await loadAdminOverview();
  await loadAdminUsers();
  await loadAdminAuditLogs();
}

async function loadAdminOverview() {
  try {
    const res = await fetch("/api/admin/overview");
    if (!res.ok) return;
    const data = await res.json();

    const uEl = document.getElementById("admin-stat-users");
    const eEl = document.getElementById("admin-stat-emails");
    const unreadEl = document.getElementById("admin-stat-unread");
    const pEl = document.getElementById("admin-stat-pending");
    const thrEl = document.getElementById("admin-stat-threats");
    const badgeEl = document.getElementById("badge-admin-count");

    if (uEl) uEl.textContent = data.total_tenants || 0;
    if (eEl) eEl.textContent = data.total_emails_ingested || 0;
    if (unreadEl) unreadEl.textContent = `${data.total_unread_emails || 0} total unread across system`;
    if (pEl) pEl.textContent = data.total_pending_approvals || 0;
    if (thrEl) thrEl.textContent = `${data.threats_blocked || 0} prompt threats neutralized`;
    if (badgeEl) badgeEl.textContent = `${data.total_tenants || 0} Users`;
  } catch (e) {
    console.error("Error loading admin overview:", e);
  }
}

async function loadAdminUsers() {
  try {
    const res = await fetch("/api/admin/users");
    if (!res.ok) return;
    _cachedAdminUsers = await res.json();
    const countBadge = document.getElementById("admin-user-count-badge");
    if (countBadge) countBadge.textContent = `${_cachedAdminUsers.length} tenants`;

    const searchVal = document.getElementById("admin-user-search")?.value.trim().toLowerCase() || "";
    renderAdminUsersTable(searchVal);
  } catch (e) {
    console.error("Error loading admin users:", e);
  }
}

function renderAdminUsersTable(filter = "") {
  const tbody = document.getElementById("admin-users-table-body");
  if (!tbody) return;

  const filtered = _cachedAdminUsers.filter(u => {
    if (!filter) return true;
    return (
      (u.user_id || "").toLowerCase().includes(filter) ||
      (u.email || "").toLowerCase().includes(filter) ||
      (u.provider || "").toLowerCase().includes(filter) ||
      (u.display_name || "").toLowerCase().includes(filter)
    );
  });

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-dim); padding: 30px;">No matching tenants found.</td></tr>`;
    return;
  }

  const activeTenantId = localStorage.getItem("automail_user_id") || "default";

  tbody.innerHTML = filtered.map(u => {
    const isCurrent = u.user_id === activeTenantId;
    let providerClass = "custom";
    const pLower = (u.provider || "").toLowerCase();
    if (pLower.includes("gmail")) providerClass = "gmail";
    else if (pLower.includes("outlook") || pLower.includes("office365")) providerClass = "outlook";
    else if (pLower.includes("yahoo")) providerClass = "yahoo";

    const statusBadge = u.status === "Active"
      ? `<span class="badge badge-success">● Active</span>`
      : `<span class="badge badge-neutral">Setup Pending</span>`;

    return `
      <tr style="${isCurrent ? 'background: rgba(99, 102, 241, 0.08);' : ''}">
        <td>
          <div style="display: flex; align-items: center; gap: 8px;">
            <span class="tenant-tag">${escapeHtml(u.user_id)}</span>
            ${isCurrent ? '<span class="badge badge-primary" style="font-size: 0.65rem;">Active Workspace</span>' : ''}
          </div>
        </td>
        <td>
          <div style="display: flex; flex-direction: column; gap: 3px;">
            <span style="font-weight: 500; color: #fff;">${escapeHtml(u.email)}</span>
            <div>
              <span class="provider-chip ${providerClass}">${escapeHtml(u.provider)}</span>
            </div>
          </div>
        </td>
        <td>
          <span style="font-weight: 600; color: #fff;">${u.total_emails}</span>
          <span style="color: var(--text-dim); font-size: 0.72rem;"> msgs</span>
        </td>
        <td>
          ${u.unread_emails > 0
            ? `<span style="color: var(--accent-secondary); font-weight: 600;">${u.unread_emails}</span>`
            : `<span style="color: var(--text-dim);">0</span>`}
        </td>
        <td>
          ${u.pending_approvals > 0 
            ? `<span class="badge badge-urgent" style="font-weight: 600;">${u.pending_approvals} pending</span>` 
            : `<span style="color: var(--text-dim); font-size: 0.78rem;">0 pending</span>`}
        </td>
        <td>
          <span style="color: var(--accent-emerald); font-weight: 500;">${u.sent_count || 0}</span>
        </td>
        <td>
          <span style="color: var(--text-dim); font-size: 0.74rem;">${escapeHtml(u.last_sync || 'Never')}</span>
        </td>
        <td>${statusBadge}</td>
        <td style="text-align: right;">
          <div class="admin-action-btn-group">
            <button class="btn btn-secondary btn-sm" onclick="adminSyncUser('${escapeHtml(u.user_id)}')" title="Trigger sync for this mailbox">
              ⚡ Sync
            </button>
            <button class="btn btn-secondary btn-sm" onclick="adminInspectUser('${escapeHtml(u.user_id)}')" title="Inspect user telemetry">
              🔍 Inspect
            </button>
            ${!isCurrent ? `
              <button class="btn btn-primary btn-sm" onclick="switchTenant('${escapeHtml(u.user_id)}')" title="Switch to user view">
                Switch
              </button>
            ` : ''}
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

async function adminSyncUser(userId) {
  showToast(`Initiating sync for tenant '${userId}'...`, "info");
  try {
    const res = await fetch(`/api/admin/users/${encodeURIComponent(userId)}/sync`, {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });
    const data = await res.json();
    if (res.ok && data.success) {
      const details = data.details || {};
      showToast(`Synced '${userId}': ${details.count || 0} new emails.`, "success");
      await loadAdminUsers();
      await loadAdminOverview();
    } else {
      showToast(`Failed to sync '${userId}': ${data.detail || 'Error'}`, "error");
    }
  } catch (e) {
    showToast(`Sync error: ${e.message}`, "error");
  }
}

async function adminSyncAll() {
  const btn = document.getElementById("btn-admin-sync-all");
  if (btn) btn.disabled = true;
  showToast("Triggering global sync across all mailboxes...", "info");

  try {
    const res = await fetch("/api/admin/sync-all", {
      method: "POST",
      headers: { "Content-Type": "application/json" }
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`Global sync completed! Processed ${data.synced_tenants} active tenants.`, "success");
      await loadAdminView();
    } else {
      showToast("Global sync failed.", "error");
    }
  } catch (e) {
    showToast(`Global sync error: ${e.message}`, "error");
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function loadAdminAuditLogs() {
  const terminal = document.getElementById("admin-audit-logs-view");
  if (!terminal) return;

  try {
    const res = await fetch("/api/admin/audit-logs?limit=100");
    if (!res.ok) return;
    const logs = await res.json();

    if (logs.length === 0) {
      terminal.innerHTML = `<div style="color: var(--text-dim); text-align: center; padding: 20px;">No audit events recorded yet.</div>`;
      return;
    }

    terminal.innerHTML = logs.map(l => `
      <div class="log-line">
        <span class="log-time">[${escapeHtml(l.timestamp)}]</span>
        <span class="tenant-tag" style="margin-right: 4px;">[${escapeHtml(l.tenant_id || 'system')}]</span>
        <span class="log-cat">[${escapeHtml(l.category)}]</span>
        <span class="log-level-${escapeHtml(l.level)}">[${escapeHtml(l.level)}]</span>
        <span style="color: #e2e8f0;">${escapeHtml(l.message)}</span>
      </div>
    `).join("");
  } catch (e) {
    console.error("Error loading admin audit logs:", e);
  }
}

async function adminInspectUser(userId) {
  try {
    const res = await fetch(`/api/admin/users/${encodeURIComponent(userId)}/inspect`);
    if (!res.ok) {
      showToast("Failed to fetch tenant inspection data", "error");
      return;
    }
    const data = await res.json();
    const modalTitle = document.getElementById("inspect-modal-title");
    const modalBody = document.getElementById("inspect-modal-body");
    const switchBtn = document.getElementById("btn-inspect-switch-to-user");

    if (modalTitle) modalTitle.textContent = `Tenant Telemetry: ${data.user_id}`;
    if (switchBtn) {
      switchBtn.onclick = () => {
        closeModal("modal-inspect-user");
        switchTenant(data.user_id);
      };
    }

    const st = data.stats || {};
    const emails = data.recent_emails || [];
    const rules = data.rules || [];

    if (modalBody) {
      modalBody.innerHTML = `
        <div class="inspect-grid">
          <div class="inspect-metric-box">
            <div class="inspect-metric-label">Connected Email</div>
            <div style="font-size: 0.85rem; font-weight: 600; color: #fff; word-break: break-all;">${escapeHtml(data.email)}</div>
          </div>
          <div class="inspect-metric-box">
            <div class="inspect-metric-label">Total Ingested</div>
            <div class="inspect-metric-val">${st.total_emails || 0}</div>
          </div>
          <div class="inspect-metric-box">
            <div class="inspect-metric-label">Pending Approvals</div>
            <div class="inspect-metric-val" style="color: var(--accent-rose);">${st.pending_approvals || 0}</div>
          </div>
        </div>

        <div style="margin-bottom: 14px;">
          <h5 style="font-size: 0.85rem; color: var(--accent-secondary); margin-bottom: 8px;">Active Automation Rules (${rules.length})</h5>
          <div style="display: flex; flex-wrap: wrap; gap: 6px;">
            ${rules.map(r => `
              <span class="badge ${r.enabled ? 'badge-neutral' : ''}" style="font-size: 0.72rem;">
                ${escapeHtml(r.name)} (${escapeHtml(r.action)})
              </span>
            `).join("") || '<span style="color: var(--text-dim); font-size: 0.75rem;">No rules configured</span>'}
          </div>
        </div>

        <div>
          <h5 style="font-size: 0.85rem; color: var(--text-main); margin-bottom: 8px;">Recent Emails in Isolated Mailbox</h5>
          <div style="max-height: 160px; overflow-y: auto; background: var(--bg-surface-elevated); border-radius: var(--radius-sm); border: 1px solid var(--border-subtle); padding: 8px;">
            ${emails.map(e => `
              <div style="padding: 6px 8px; border-bottom: 1px solid var(--border-subtle); font-size: 0.76rem; display: flex; justify-content: space-between; align-items: center;">
                <div style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 70%;">
                  <strong style="color: #fff;">${escapeHtml(e.subject)}</strong>
                  <div style="color: var(--text-dim);">${escapeHtml(e.from)}</div>
                </div>
                <span class="badge badge-neutral" style="font-size: 0.68rem;">${escapeHtml(e.category || 'General')}</span>
              </div>
            `).join("") || '<div style="color: var(--text-dim); font-size: 0.75rem; padding: 10px; text-align: center;">Mailbox is empty</div>'}
          </div>
        </div>
      `;
    }

    openModal("modal-inspect-user");
  } catch (e) {
    showToast(`Inspect error: ${e.message}`, "error");
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

// ==========================================================================
// 9. AUTHENTICATION & MULTI-USER RBAC SUBSYSTEM
// ==========================================================================

async function checkAuthStatus() {
  try {
    const res = await fetch("/api/auth/me");
    if (res.ok) {
      const data = await res.json();
      currentUser = data.user || null;
      const activeId = data.active_user_id || "default";
      localStorage.setItem("automail_user_id", activeId);
      updateUserProfileUI(data);
    }
  } catch (e) {
    console.error("Auth status error:", e);
  }
}

function updateUserProfileUI(authData) {
  const user = authData?.user;
  const activeId = authData?.active_user_id || "default";
  const role = authData?.role || (activeId === "default" ? "admin" : "user");
  const email = authData?.email || `${activeId}@automail.local`;
  const name = authData?.name || user?.name || (activeId === "default" ? "Admin Account" : activeId);

  // Update Sidebar Profile Card
  const nameEl = document.getElementById("sidebar-user-name");
  const emailEl = document.getElementById("sidebar-user-email");
  const avatarEl = document.getElementById("sidebar-user-avatar");
  const roleEl = document.getElementById("sidebar-user-role");

  if (nameEl) nameEl.textContent = name;
  if (emailEl) emailEl.textContent = email;
  if (avatarEl) avatarEl.textContent = (name || "U")[0].toUpperCase();
  if (roleEl) {
    roleEl.textContent = role === "admin" ? "Admin" : "User";
    roleEl.className = `badge ${role === "admin" ? "badge-primary" : "badge-neutral"} user-role-badge`;
  }

  // Update Topbar
  const topbarAuthLabel = document.getElementById("topbar-auth-label");
  if (topbarAuthLabel) {
    topbarAuthLabel.textContent = localStorage.getItem("automail_token") ? "Account" : "Sign In";
  }
  const currentBadge = document.getElementById("current-user-badge");
  if (currentBadge) {
    currentBadge.textContent = `User: ${activeId}`;
  }

  // RBAC: Show or Hide Admin Nav Item
  const adminNav = document.getElementById("nav-admin");
  if (adminNav) {
    if (role === "admin") {
      adminNav.style.display = "flex";
    } else {
      adminNav.style.display = "none";
      if (currentView === "admin") {
        switchView("overview");
      }
    }
  }
}

function openAuthModal(tab = "login") {
  setAuthTab(tab);
  const alertEl = document.getElementById("auth-alert");
  if (alertEl) alertEl.style.display = "none";
  openModal("modal-auth");
}

function setAuthTab(tab) {
  const tabLogin = document.getElementById("tab-login");
  const tabRegister = document.getElementById("tab-register");
  const formLogin = document.getElementById("form-login");
  const formRegister = document.getElementById("form-register");
  const modalTitle = document.getElementById("auth-modal-title");

  if (tab === "login") {
    tabLogin?.classList.add("active");
    tabRegister?.classList.remove("active");
    if (formLogin) formLogin.style.display = "block";
    if (formRegister) formRegister.style.display = "none";
    if (modalTitle) modalTitle.textContent = "Sign In to Workspace";
  } else {
    tabLogin?.classList.remove("active");
    tabRegister?.classList.add("active");
    if (formLogin) formLogin.style.display = "none";
    if (formRegister) formRegister.style.display = "block";
    if (modalTitle) modalTitle.textContent = "Create Isolated Account";
  }
}

async function submitLogin() {
  const email = document.getElementById("login-email")?.value.trim();
  const password = document.getElementById("login-password")?.value;
  const alertEl = document.getElementById("auth-alert");
  const btn = document.getElementById("btn-submit-login");

  if (!email || !password) return;
  if (btn) btn.disabled = true;

  try {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      localStorage.setItem("automail_token", data.token);
      localStorage.setItem("automail_user_id", data.user.id);
      closeModal("modal-auth");
      showToast(`Welcome back, ${data.user.name || data.user.email}!`, "success");
      await checkAuthStatus();
      selectedEmailId = null;
      await loadAllData(false);
      await loadSettings();
    } else {
      if (alertEl) {
        alertEl.className = "auth-alert error";
        alertEl.style.display = "flex";
        alertEl.textContent = data.detail || "Invalid email or password.";
      }
    }
  } catch (e) {
    if (alertEl) {
      alertEl.className = "auth-alert error";
      alertEl.style.display = "flex";
      alertEl.textContent = "Network error: " + e.message;
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function submitRegister() {
  const name = document.getElementById("reg-name")?.value.trim();
  const email = document.getElementById("reg-email")?.value.trim();
  const password = document.getElementById("reg-password")?.value;
  const alertEl = document.getElementById("auth-alert");
  const btn = document.getElementById("btn-submit-register");

  if (!email || !password) return;
  if (btn) btn.disabled = true;

  try {
    const res = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, display_name: name })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      localStorage.setItem("automail_token", data.token);
      localStorage.setItem("automail_user_id", data.user.id);
      closeModal("modal-auth");
      showToast(`Account created! Welcome, ${data.user.name || data.user.email}.`, "success");
      await checkAuthStatus();
      selectedEmailId = null;
      await loadAllData(false);
      await loadSettings();
    } else {
      if (alertEl) {
        alertEl.className = "auth-alert error";
        alertEl.style.display = "flex";
        alertEl.textContent = data.detail || "Registration failed.";
      }
    }
  } catch (e) {
    if (alertEl) {
      alertEl.className = "auth-alert error";
      alertEl.style.display = "flex";
      alertEl.textContent = "Network error: " + e.message;
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function handleGoogleSignIn() {
  const btnText = document.getElementById("google-btn-text");
  if (btnText) btnText.textContent = "Connecting to Google...";

  try {
    const res = await fetch("/api/auth/google/url");
    const data = await res.json();

    if (data.configured && data.url) {
      // Redirect to official Google OAuth consent screen
      window.location.href = data.url;
      return;
    }

    // If Google credentials are not yet entered in .env, offer immediate Demo Google Sign-In
    showToast("Google credentials pending in .env. Initializing 1-Click Google Account Sign-In...", "info");
    const demoRes = await fetch("/api/auth/google/demo", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "user.google@gmail.com",
        name: "Google Connected User"
      })
    });
    const demoData = await demoRes.json();
    if (demoRes.ok && demoData.success) {
      localStorage.setItem("automail_token", demoData.token);
      localStorage.setItem("automail_user_id", demoData.user.id);
      closeModal("modal-auth");
      showToast(`Logged in with Google as ${demoData.user.email}! (Tenant: ${demoData.user.id})`, "success");
      await checkAuthStatus();
      selectedEmailId = null;
      await loadAllData(false);
      await loadSettings();
    } else {
      showToast("Google sign in error", "error");
    }
  } catch (e) {
    showToast("Google Sign-In error: " + e.message, "error");
  } finally {
    if (btnText) btnText.textContent = "Continue with Google";
  }
}

async function handleSignOutOrOpen() {
  const token = localStorage.getItem("automail_token");
  if (token) {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch (e) {}
    localStorage.removeItem("automail_token");
    localStorage.setItem("automail_user_id", "default");
    showToast("Signed out successfully. Switched to Default Account.", "info");
    await checkAuthStatus();
    selectedEmailId = null;
    await loadAllData(false);
    await loadSettings();
  } else {
    openAuthModal("login");
  }
}
