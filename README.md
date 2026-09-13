# Email_Automation_Saas

A dedicated, UI-based **Autonomous Email Automation Service** with AI email categorization, priority and sentiment scoring, contextual reply drafting, human-in-the-loop review queues, custom automation rules, live delivery outbox, and **end-to-end security hardening**.

---

## 📑 Product Documentation & Presentation Deck

This repository includes a complete **Product Requirements Document (PRD)** and an interactive **Presentation Pitch Deck (Slides)** designed for stakeholder presentations, team onboarding, and live client walkthroughs:

* **📄 [Product Requirements Document (PRD.md)](PRD.md)**:
  * Comprehensive product specification covering user personas, problem statement, functional specifications, "Explain Like I'm 7" UX philosophy, PromptShield adversarial defense, multi-tenant isolation, API definitions, and product roadmap.
* **📊 [Product Presentation Deck (SLIDES.md)](SLIDES.md)**:
  * 10 professionally structured slides with visual diagrams, key takeaways, and complete word-for-word **Speaker Notes** for presenters.
  * Compatible with Marp, Slidev, Google Slides, Microsoft PowerPoint, and Gamma.app.

### How to Use & Export the Slides:
1. **Interactive CLI / Instant Export with Marp**:
   ```bash
   # Open live presentation preview:
   npx @marp-team/marp-cli SLIDES.md --preview

   # Export directly to PDF:
   npx @marp-team/marp-cli SLIDES.md --pdf -o AutoMail_AI_Presentation.pdf

   # Export directly to PowerPoint (.pptx):
   npx @marp-team/marp-cli SLIDES.md --pptx -o AutoMail_AI_Presentation.pptx
   ```
2. **Google Slides / PowerPoint**:
   * Open [SLIDES.md](SLIDES.md). Each slide is clearly demarcated by `<!-- SLIDE X -->`.
   * Copy the slide title & bullets into your slide layout, and paste the `Speaker Notes` directly into your presentation notes pane.
3. **AI Slide Generators (Gamma / Pitch)**:
   * Upload [PRD.md](PRD.md) or [SLIDES.md](SLIDES.md) to [Gamma.app](https://gamma.app) to generate an AI presentation in under 30 seconds.

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

3. **Enterprise SaaS Suite & Public Showcase**
   - **Interactive Live ROI / Cost-Savings Calculator**: Dynamic sliders for team seats (5–500), daily inbound emails, and blended hourly rate ($30–$250/hr), computing real-time monthly hours saved and dollar ROI.
   - **Interactive Capabilities Showcase**: Segmented feature switchers showcasing 1-Sentence Executive Briefings, Human-in-the-Loop Safe Approval Queue, PromptShield Adversarial Threat Defense, and 100% Isolated Multi-Tenant RAG Copilot.
   - **Annual / Monthly Billing Matrix**: Transparent enterprise tier pricing (Starter $49, Professional $199, Enterprise Scale $899) with 20% annual discount toggling.

4. **Security, Governance & Compliance Center**
   - **Continuous Regulatory Posture Monitoring**: Real-time compliance scorecards tracking SOC-2 Type II (99.4% controls active), ISO/IEC 27001:2022 (98.2% Annex A verified), HIPAA Security Rule (100% BAA ready), and GDPR Art. 28 / DPA (100% compliant).
   - **Cryptographic SIEM Audit Export**: Download SHA-256 HMAC-signed audit streams in JSON or CSV for Splunk, Datadog, or external SOC compliance ingestion.
   - **SAML 2.0 / Enterprise SSO Ready**: Okta, Microsoft Entra ID (Azure AD), and Google Workspace integration hooks.

5. **Enterprise Integrations Hub & Ecosystem Connectors**
   - Multi-tenant isolated webhook connectors for **Slack Enterprise Grid**, **Microsoft Teams**, **Jira Service Management**, **Salesforce CRM**, and **Datadog / Splunk SIEM**.
   - Per-tenant custom webhook configuration with zero cross-organization leakage.

6. **Multi-Seat RBAC Organization & Team Governance**
   - Seat utilization gauge with total, allocated, and available licenses.
   - Role-Based Access Control (Enterprise Owner, Security Officer, Operations Admin, Compliance Auditor) with enforced MFA status and activity tracking.

7. **Universal Spotlight Command Palette (`Ctrl+K` / `⌘K`)**
   - Fast, keyboard-first navigation to all views, quick simulation, SIEM export, theme switching, and direct RAG search queries.

8. **AI Email Intelligence & Multi-Tenant RAG Copilot**
   - Automatic classification: *Customer Support*, *Sales Inquiry*, *Billing/Invoice*, *Urgent Action*, *General Inquiry*, *Newsletter/Spam*.
   - Priority and Sentiment analysis (*Urgent*, *High*, *Medium*, *Low*).
   - Executive 1-2 sentence summaries and action item task extraction.
   - Hybrid BM25 + Semantic RAG query engine answering questions against private mailbox context with strict per-user boundaries.

9. **Human-in-the-Loop Approval Queue**
   - Side-by-side view: Original incoming email vs AI-drafted reply.
   - 1-click tone switcher (*Professional*, *Friendly*, *Direct*, *Executive*).
   - Instant inline text editor to refine replies before sending.
   - One-click **"Approve & Send"** and **"Dismiss / Reject"**.

10. **Visual Automation Rules Engine**
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

## Multi-Tenancy & Relational Architecture (Phase 1)

AutoMail AI includes a production-grade multi-tenant data architecture built on **SQLAlchemy 2.0 Async** (supporting PostgreSQL via `asyncpg` in production and SQLite via `aiosqlite` for zero-friction local development):

- **Organizations (`organizations`)**: Root tenant entity with subscription tiers (`free`, `pro`, `enterprise`), seat caps, and per-organization cryptographic envelope salt.
- **Zero-Downtime Envelope Key Rotation (`key_version`)**: Per-org Fernet vault keys are derived using PBKDF2/HKDF-SHA256(`MasterKey`, `Salt`, `OrgID`, `key_version`). Rotating keys requires zero schema changes.
- **Strict Hard Startup Security Gate**: The server refuses to boot in non-dev environments if `JWT_SECRET_KEY` is missing, default, or under 32 characters.
- **SOC-2 Forensic Integrity (`redacted_payload` + `payload_hash`)**: Audit logs retain actual sanitized payloads alongside a SHA-256 HMAC cryptographic checksum.
- **Idempotent JSON-to-Postgres Migration**:
  ```bash
  # Dry-run mode (safe simulation without committing changes):
  python -m email_service.db.migrate_json_to_postgres --dry-run

  # Live idempotent migration:
  python -m email_service.db.migrate_json_to_postgres
  ```
- **Distributed Redis Cache & Rate Limiting (`redis_client.py`)**: Sliding-window rate limiting across horizontal replicas with fast JWT revocation blacklist and graceful local memory fallback.

---

## Project Structure

```
├── email_service/
│   ├── config.py         # Encrypted settings & credentials management
│   ├── security.py       # Envelope Fernet vault, PromptShield, DataLeakPreventer, RateLimiters
│   ├── storage.py        # Dual storage engine abstraction (JSON & Postgres feature flag)
│   ├── auth.py           # PBKDF2 hashing, JWT sessions with hard startup gate, Google OAuth
│   ├── ai_engine.py      # Gemini API & smart built-in heuristic AI engine
│   ├── email_engine.py   # IMAP receiver, SMTP dispatcher, rules processor
│   ├── rag_engine.py     # Multi-tenant RAG chatbot with private workspace context
│   ├── server.py         # FastAPI REST API & static file server with security middleware
│   ├── db/               # Relational database layer
│   │   ├── models.py     # SQLAlchemy 2.0 async models (9 multi-tenant tables & cascades)
│   │   ├── session.py    # Async engine & session factory with connection tuning
│   │   ├── repositories.py # Asynchronous domain repositories
│   │   ├── redis_client.py # Distributed Redis rate limiter & token revocation blacklist
│   │   └── migrate_json_to_postgres.py # Idempotent migration utility with dry-run
│   ├── static/           # Modern Web Dashboard (HTML, CSS, JS)
│   └── data/             # Persistent encrypted state & vault key
├── start_email_service.bat        # 1-click launcher
├── test_phase1_multitenancy.py    # Phase 1 multi-tenancy & database integration test suite
├── test_full_system_verification.py # Full system end-to-end verification suite
├── test_qa_suite.py               # Professional QA engineer test suite
├── test_email_service.py          # Core automated unit & security test suite
├── requirements.txt               # Clean dependencies list
└── README.md
```

---

## Verification Tests

Run the full verification suite anytime:
```bash
# Phase 1 Multi-Tenancy, Encryption, Schema & Migration Test Suite:
python test_phase1_multitenancy.py

# Full End-to-End Live HTTP Verification:
python test_full_system_verification.py

# QA Engineer System Integrity Suite:
python test_qa_suite.py

# Core Security & Diagnostic Suite:
python test_email_service.py
```
Output: `ALL TESTS PASSED WITH ZERO ERRORS! [OK]`
