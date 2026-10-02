# Session Persistence After Password Reset — Security Lab

A deliberately vulnerable web application demonstrating a **session invalidation vulnerability following password reset**.

This lab is designed for cybersecurity students, penetration testers, and security researchers who want to understand how an authenticated session can remain valid after an account's password has been changed.

> ⚠️ **Educational Use Only**
>
> This application is intentionally vulnerable. Run it only on your own computer, inside a lab environment, or on infrastructure where you have explicit authorization.
>
> Do not deploy this vulnerable version to a public-facing server.

---

# Table of Contents

- [About the Lab](#about-the-lab)
- [Vulnerability](#vulnerability)
- [Application Features](#application-features)
- [Lab Architecture](#lab-architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running the Lab](#running-the-lab)
- [Opening the Application](#opening-the-application)
- [Creating an Account](#creating-an-account)
- [Testing Login and Logout](#testing-login-and-logout)
- [Testing Forgot Password](#testing-forgot-password)
- [Reproducing the Vulnerability](#reproducing-the-vulnerability)
- [Testing Ownership Transfer](#testing-ownership-transfer)
- [Understanding the Vulnerability](#understanding-the-vulnerability)
- [Expected Vulnerable Behavior](#expected-vulnerable-behavior)
- [Expected Fixed Behavior](#expected-fixed-behavior)
- [Security Fix](#security-fix)
- [Stopping the Lab](#stopping-the-lab)
- [Troubleshooting](#troubleshooting)
- [Project Structure](#project-structure)
- [Learning Objectives](#learning-objectives)
- [Disclaimer](#disclaimer)

---

# About the Lab

This project reproduces a web application session-management vulnerability.

The vulnerability occurs when a user changes their password through the account recovery process while an existing authenticated session remains active on another device.

The vulnerable application fails to invalidate the old session.

As a result:

1. Device A logs into the application.
2. Device B performs a password reset.
3. The password is successfully changed.
4. Device A still has the old authenticated session.
5. Device A refreshes the page.
6. Device A remains logged in.

A secure implementation should invalidate existing sessions after a security-sensitive account change such as a password reset.

---

# Vulnerability

## Session Persistence After Password Reset

The application intentionally demonstrates the following condition:

```text
Existing authenticated session
          |
          v
Password reset occurs
          |
          v
Password is changed
          |
          v
Old session remains valid
          |
          v
Previously authenticated device
remains logged in
