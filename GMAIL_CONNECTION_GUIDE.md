# 📬 AutoMail AI — Complete Gmail Connection Guide

A complete, beginner-friendly guide to connecting your **Google Gmail** or **Google Workspace** account to AutoMail AI in under 2 minutes.

---

## 🔒 Why Do You Need a Google App Password?

For security, Google does not allow external applications to log in using your primary Google account password. Instead, Google uses **App Passwords**:
- A unique, randomly generated **16-letter passcode** created specifically for AutoMail AI.
- Your primary Google password is **never exposed**.
- Encrypted on disk using **AES-256 Fernet** hardware envelope encryption inside your isolated tenant vault.
- Can be revoked at any time from your Google Account with a single click.

---

## 📋 Prerequisites

Before starting, ensure **2-Step Verification (2FA)** is turned on for your Google Account.
> If 2-Step Verification is not turned on, Google will not show the App Passwords option.

1. Go to your [Google Account Security Settings](https://myaccount.google.com/security).
2. Look for **"How you sign in to Google"** > **"2-Step Verification"**.
3. If it says *Off*, click it and follow the on-screen steps to turn it **ON** using your phone or authenticator app.

---

## 🚀 Step-by-Step Connection Instructions

### Step 1: Generate Your 16-Letter Google App Password

1. Open the [Google App Passwords Page](https://myaccount.google.com/apppasswords) in your browser.
   *(You may be asked to re-enter your Google password to verify your identity).*
2. In the **"App name"** text box, type:
   ```text
   AutoMail
   ```
3. Click the blue **"Create"** button.
4. A popup will appear showing a **16-letter password** in a yellow box, for example:
   ```text
   abcd efgh ijkl mnop
   ```
5. **Copy this 16-letter code** (or keep the window open). You will paste this into AutoMail.
6. Click **"Done"** in the Google popup.

---

### Step 2: Enter Your Credentials in AutoMail AI

1. Open your AutoMail AI Dashboard at [http://localhost:8000](http://localhost:8000).
2. In the left sidebar, click **⚙️ Settings** (or navigate to `http://localhost:8000/#settings`).
3. Under **"1-Click Provider Preset"**, ensure **🔴 Gmail** is highlighted (it is selected by default). This automatically configures:
   | Setting | Value | Description |
   |---|---|---|
   | **IMAP Server** | `imap.gmail.com` | Incoming Mail Server |
   | **IMAP Port** | `993` | SSL/TLS Encrypted |
   | **SMTP Server** | `smtp.gmail.com` | Outgoing Mail Server |
   | **SMTP Port** | `587` | STARTTLS Encrypted |

4. In the **Email Address** field, enter your full Gmail address:
   ```text
   your.name@gmail.com
   ```
   *(Or your custom domain Google Workspace address, e.g., `alex@yourcompany.com`).*

5. In the **App Password / Token** field, paste the **16-letter code** you copied in Step 1:
   ```text
   abcdefghijklmnop
   ```
   *(Spaces between letters are automatically handled).*

---

### Step 3: Test & Save the Connection

1. Click the **"Test Connection Diagnostics"** button.
2. AutoMail will execute an immediate live cryptographic handshake with Google's servers. Within 2 seconds, you should see:
   > 🟢 **✓ Connection successful! Both IMAP (reading) and SMTP (sending) verified.**
3. Scroll down and click **"Save Configuration"** (or **"Save & Apply Settings"**).
4. A notification will confirm: *“Settings saved & encrypted with AES-256 Fernet”*.

---

### Step 4: Ingest & Automate Your Inbox

1. In the sidebar, click **"Check for New Emails"** (or click **"Sync Mail"** in the top header).
2. AutoMail connects to `imap.gmail.com`, ingests your unread messages, and automatically:
   - 🛡️ Filters threats and prompt injections via **PromptShield**.
   - 💡 Generates **1-Sentence Plain-English Executive Briefings**.
   - 📋 Extracts an **Actionable Task Checklist**.
   - ✍️ Prepares contextual replies in the **Waiting for Your OK** review queue.

---

## 🏢 Special Instructions for Google Workspace (Company Email)

If you use a company Google Workspace account (e.g. `@yourcompany.com`) and don't see the App Passwords option:
1. Your Google Workspace Administrator must enable 2-Step Verification for the domain.
2. The administrator must allow users to create App Passwords:
   - Go to Google Admin Console (`admin.google.com`) > **Security** > **Authentication** > **2-step verification**.
   - Ensure **"Allow users to turn on 2-step verification"** is checked.
   - Check **"Allow users to generate application-specific passwords"**.

---

## ❓ Frequently Asked Questions & Troubleshooting

### Q1: I get an "Invalid Credentials" or "Authentication Failed" error.
- **Cause 1**: You entered your standard Google account password instead of the 16-letter App Password.
  - *Fix*: Google blocks standard passwords on IMAP. You must generate a dedicated App Password at [https://myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).
- **Cause 2**: 2-Step Verification is disabled on your Google account.
  - *Fix*: Enable 2-Step Verification in [Security Settings](https://myaccount.google.com/security), then create a new App Password.
- **Cause 3**: Typo in the email address or App Password.
  - *Fix*: Re-copy the 16 letters and make sure your email ends in `@gmail.com` (or your valid domain).

### Q2: I don't see "App Passwords" in my Google Account settings.
- Direct URL: Navigate directly to [https://myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords).
- Search bar: In your Google Account search bar at the top, type *"App passwords"*.
- If it still doesn't appear, 2-Step Verification is either off or was turned on just seconds ago (wait 60 seconds and refresh).

### Q3: How do I disconnect or revoke access?
- In AutoMail AI: Go to **Settings** > click **Clear / Reset**.
- In Google: Visit [Google App Passwords](https://myaccount.google.com/apppasswords) and click the **Trash Can icon** next to *AutoMail*. Access is revoked instantly.

### Q4: Are my emails or passwords sent to third-party servers?
- **No**. AutoMail AI runs completely locally or in your private isolated tenant database.
- Credentials are encrypted using **Hardware AES-256 Fernet encryption** at rest and never shared.
- AutoMail communicates directly between your machine and `imap.gmail.com` / `smtp.gmail.com` over TLS 1.3.

---

## 🌐 Other Supported Email Providers

AutoMail AI also supports other providers with 1-click presets:
- **Microsoft Outlook / Office 365**: `outlook.office365.com:993` / `smtp.office365.com:587`
- **Yahoo Mail**: `imap.mail.yahoo.com:993` / `smtp.mail.yahoo.com:587` (requires Yahoo App Password)
- **Apple iCloud**: `imap.mail.me.com:993` / `smtp.mail.me.com:587` (requires Apple App-Specific Password)
- **Custom Corporate IMAP/SMTP**: Any custom host and SSL/TLS port.
