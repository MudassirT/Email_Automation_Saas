# Email_Automation_Saas

A dedicated, UI-based **Autonomous Email Automation Service** with AI email categorization, priority and sentiment scoring, contextual reply drafting, human-in-the-loop review queues, custom automation rules, live delivery outbox, and **end-to-end security hardening**.

---

## Key Features

1. **Standalone Web Dashboard (`http://localhost:8000`)**
   - Zero terminal/file-vault orchestrator overhead.
   - Built with a modern glassmorphic interface, dark theme, and micro-animations.

2. **End-to-End Security Hardening**
   - **Encrypted-at-Rest Secret Vault**: 256-bit Fernet AES encryption for passwords and API keys on disk (`.vault_key`). Secrets are masked on all API responses (`••••••••••••••••`).
   - **Prompt Injection Defense (`PromptShield`)**: Real-time heuristic scanning of incoming subjects & bodies for adversarial attacks (`ignore instructions`, `override system prompt`). Quarantines malicious emails and freezes automated execution.
   - **Isolated Context Boundaries**: Untrusted customer emails are wrapped in secure XML tags with strict system instructions forbidding prompt execution.
   - **Sensitive Data Leakage Prevention (`DataLeakPreventer`)**: Scans all AI-generated draft responses before display or sending; automatically redacts API keys, private keys, passwords, or tokens.
   - **Web API Hardening**: Content-Security-Policy (CSP), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, Referrer Policy, and strict localhost CORS lock.
   - **Anti-CSRF Protection**: Blocks unauthorized cross-origin mutation requests.
   - **Dispatch Rate Limiting**: Maximum 30 emails per hour sliding-window guardrail to prevent runaway email loops.
   - **Recipient Validation**: RFC-compliant email verification and automatic blocking of disposable/burner domains.

3. **AI Email Intelligence**
   - Automatic classification: *Customer Support*, *Sales Inquiry*, *Billing/Invoice*, *Urgent Action*, *General Inquiry*, *Newsletter/Spam*.
   - Priority and Sentiment analysis (*Urgent*, *High*, *Medium*, *Low*).
   - Executive 1-2 sentence summaries for fast scanning.

4. **Human-in-the-Loop Approval Queue**
   - Side-by-side view: Original incoming email vs AI-drafted reply.
   - 1-click tone switcher (*Professional*, *Friendly*, *Direct*, *Executive*).
   - Instant inline text editor to refine replies before sending.
   - One-click **"Approve & Send"** and **"Dismiss / Reject"**.

5. **Visual Automation Rules Engine**
   - Custom triggers (*Subject*, *Sender*, *Category*, *Priority*) with operators (*contains*, *equals*, *starts_with*).
   - Actions: Auto-generate draft, Mark urgent, Assign category, Auto-send.
   - Instant toggle switches to enable/disable rules.

---

## Quick Start

### 1. Launch the Service
Double-click `start_email_service.bat` or run:
```bash
python -m email_service.server
```
Your browser will automatically open to **http://localhost:8000**.

### 2. Configure Settings
1. Navigate to **Settings & Keys** in the web dashboard.
2. Enter your Gmail address and 16-character [Google App Password](https://myaccount.google.com/apppasswords).
3. (Optional) Enter your Google Gemini API key.
4. Click **"Test Connection Diagnostics"** and **"Save & Apply Settings"**.

### 3. Test with Simulated Email
Click **"Simulate Email"** in the top bar to test:
- 🚨 Urgent Customer Support ticket
- 💼 High-Value Sales Lead
- 💳 Billing Query
- 🛡️ **Adversarial Prompt Injection Attack** (tests prompt injection quarantine in real-time!)

---

## Project Structure

```
├── email_service/
│   ├── config.py         # Encrypted settings & credentials management
│   ├── security.py       # Fernet vault, PromptShield, DataLeakPreventer, RateLimiters
│   ├── storage.py        # Local persistent state (emails, drafts, rules, logs)
│   ├── ai_engine.py      # Gemini API & smart built-in heuristic AI engine
│   ├── email_engine.py   # IMAP receiver, SMTP dispatcher, rules processor
│   ├── server.py         # FastAPI REST API & static file server with security middleware
│   ├── static/           # Modern Web Dashboard (HTML, CSS, JS)
│   └── data/             # Persistent encrypted state & vault key
├── start_email_service.bat  # 1-click launcher
├── test_email_service.py    # Automated test suite (with security tests)
├── requirements.txt         # Clean dependencies list
└── README.md
```

---

## Verification Tests

Run the automated test suite anytime:
```bash
python test_email_service.py
```
Output: `ALL AUTOMATED VERIFICATION TESTS PASSED! [OK]`
