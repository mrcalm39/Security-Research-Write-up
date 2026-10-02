# Session Invalidation Vulnerability

## Summary

An authenticated session remains valid after a password reset when the application changes the password without revoking previously issued sessions.

## Reproduction

1. Log in as Alice.
2. Record the local lab `PHPSESSID`.
3. Reuse that session in a second local browser context.
4. Reset Alice's password in the first context.
5. Request `/dashboard` from the second context using the old session.
6. In vulnerable mode, the old session remains authenticated and can reach owner actions such as `/invite` and `/transfer`.

## Root cause

The vulnerable password-reset path updates the password but deliberately does not delete the user's existing server-side sessions or invalidate their session version.

## Remediation

The fixed path deletes existing sessions and increments the user's session version. A new login is therefore required after reset.

This project is an intentionally vulnerable local training application. Do not deploy vulnerable mode publicly.
