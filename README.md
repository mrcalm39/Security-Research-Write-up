# Security-Research-Write-up
Anonymized research detailing broken session management flaws and horizontal privilege escalation via persistent cookies.

# Lab: Broken Session Management (Stale Session Vulnerability)

## 📌 Executive Summary
This repository contains anonymized security research detailing a critical **Broken Session Management** flaw discovered in a production web application. The application failed to invalidate active session identifiers following an account password reset initiated via the "forgotten password" flow. This logical flaw allowed an active session on a separate device to persist indefinitely, granting unauthorized access to deep administrative capabilities.

---

## 🔍 Vulnerability Profile
* **Vulnerability Type:** Broken Session Management / Weak Session Invalidation
* **Vulnerability Classification:** Insufficient Session Expiration (Stale Session)
* **Severity:** **High** 🔴
* **Impact:** Administrative Account Takeover (ATO) & Unauthorized Privilege Persistence

---

## 🕹️ Technical Breakdown & Scenario
In a secure web architecture, executing a password change or recovery must destroy all active session tokens cached or stored across concurrent devices to isolate the account. 

In this application, while the password modification successfully updated the backend database, the session tracking layer failed to terminate or audit active cookies running on concurrent browsers.

### Step-by-Step Replication Sequence
1. **Initial Access:** A user session was established on **Device A**, keeping the application interface fully active.
2. **Account Recovery Trigger:** On **Device B**, the user explicitly logged out, navigated to the login portal, and selected the **"Forgotten Password"** option.
3. **Password Modification:** The user successfully completed the external reset verification link, updated their account password, and logged back in using the new credentials on **Device B**.
4. **Vulnerability Verification:** Returning to **Device A** (which still held the pre-existing session token), the page was refreshed. 
5. **Persistence Confirmed:** The application failed to drop the session or redirect to a login prompt. The stale session remained fully authenticated and operational.

---

## ⚡ Business & Security Impact (Post-Exploitation)
Because the old session was not invalidated, an attacker possessing a stale cookie maintained persistent, high-privilege access. On **Device A**, the session allowed full execution of administrative, high-impact tasks including:
* **API Key Exploitation:** Generating new programmatic API keys to permanently drain or manipulate data via background scripts.
* **Data Destruction:** Modifying and deleting critical application records.
* **Access Expansion:** Inviting malicious external users to the organization platform.
* **Complete Compromise:** Modifying and transferring account ownership, completely locking out the legitimate account owner.

---

## 🛠️ Remediation Strategy
The organization successfully resolved this issue by implementing the following controls:
* **Global Session Revocation:** Enforced backend configurations to explicitly clear and invalidate all database/cache session identifiers associated with the User ID immediately upon a password reset execution.
* **Re-Authentication Prompts:** Configured the application to actively challenge any remaining open windows to re-authenticate if their session state detects a mismatch with the updated user security stamp.
