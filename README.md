# PHPSESSID Session Invalidation Lab

A beginner-friendly Docker lab demonstrating **improper session invalidation after password reset**.

## Learning goal

The lab answers one question:

> After a password reset, can an old authenticated `PHPSESSID` still access the account?

It has two modes:

- `vulnerable` — old sessions remain valid.
- `fixed` — old sessions are revoked.

## Requirements

- Docker
- A web browser
- Git (optional)

Python is not required when using Docker.

## Download

Clone your GitHub repository:

```bash
git clone https://github.com/YOUR_USERNAME/session-invalidation-lab.git
cd session-invalidation-lab
```

Or download the GitHub ZIP and extract it.

## Build

```bash
docker build -t session-invalidation-lab .
```

## Run vulnerable mode

```bash
docker run --name session-invalidation-lab \
  -p 5000:5000 \
  -e LAB_MODE=vulnerable \
  session-invalidation-lab
```

Open:

```text
http://127.0.0.1:5000
```

## Default accounts

```text
Alice
Email: alice@example.test
Password: password123
Role: owner

Bob
Email: bob@example.test
Password: password123
Role: member
```

## Beginner walkthrough

### 1. Login

Open `/login` and log in as Alice.

### 2. Inspect the cookie

Open browser developer tools and find the cookie named:

```text
PHPSESSID
```

The lab intentionally uses this cookie name so session handling is easy to observe.

### 3. Create two browser contexts

Use a normal browser window and a private/incognito window to represent Device A and Device B.

For this local lab exercise, reproduce Alice's lab session in the second context using the `PHPSESSID` value from the first context. Browser cookie-editing interfaces differ; a local cookie-testing extension can be used if the browser does not provide editing controls.

Only do this with sessions belonging to your own local lab or systems you are explicitly authorized to test.

### 4. Reset the password

In Device A, open:

```text
http://127.0.0.1:5000/forgot
```

Enter:

```text
alice@example.test
```

Open the generated reset link and set a new password such as:

```text
NewPassword123!
```

### 5. Test the old session

Return to Device B and request:

```text
http://127.0.0.1:5000/dashboard
```

In vulnerable mode, the old `PHPSESSID` is still accepted.

### 6. Demonstrate authorization impact

With the old session, open:

```text
http://127.0.0.1:5000/invite
```

and:

```text
http://127.0.0.1:5000/transfer
```

The old session can still reach these owner actions because the server still considers it authenticated as Alice.

## Fixed mode

Stop the vulnerable container:

```bash
docker rm -f session-invalidation-lab
```

Run fixed mode:

```bash
docker run --name session-invalidation-lab \
  -p 5000:5000 \
  -e LAB_MODE=fixed \
  session-invalidation-lab
```

Repeat the same exercise. After the password reset, the old session should no longer access `/dashboard`; it should be sent back to login.

## Vulnerable vs fixed

| Behavior | Vulnerable | Fixed |
|---|---|---|
| Password reset works | Yes | Yes |
| Existing sessions revoked | No | Yes |
| Old PHPSESSID remains authenticated | Yes | No |
| Old session reaches dashboard | Yes | No |
| Old session reaches owner actions | Yes | No |
| New login required | No | Yes |

## Technical explanation

The browser receives a `PHPSESSID` cookie. The Flask session contains a random server-side session token. That token points to a record in the SQLite `sessions` table.

Simplified flow:

```text
PHPSESSID
   |
   v
Flask session
   |
   v
session_token
   |
   v
sessions table
   |
   v
user_id
   |
   v
users table
```

In vulnerable mode, password reset changes the password but does not remove the existing session record.

In fixed mode, password reset:

```python
DELETE FROM sessions WHERE user_id = ?
```

and increments the user's `session_version`.

## Health check

Open:

```text
http://127.0.0.1:5000/health
```

## Useful Docker commands

```bash
docker ps
docker logs session-invalidation-lab
docker stop session-invalidation-lab
docker rm session-invalidation-lab
docker rm -f session-invalidation-lab
```

## Reset the database

The lab database is `lab.db` and is ignored by Git.

For a local non-Docker run, delete it and restart the app:

```bash
rm -f lab.db
```

The default users will be recreated.

## Project structure

```text
session-invalidation-lab/
├── app.py
├── Dockerfile
├── requirements.txt
├── .dockerignore
├── .gitignore
├── README.md
├── docs/
│   └── SECURITY_WRITEUP.md
├── static/
│   └── style.css
└── templates/
    ├── accept_invite.html
    ├── base.html
    ├── dashboard.html
    ├── forgot.html
    ├── index.html
    ├── invite.html
    ├── login.html
    ├── reset.html
    └── transfer.html
```

## Important security warning

This repository intentionally contains a vulnerable mode. Do not expose it to the public internet. Use it for local learning, authorized testing, security training, and portfolio demonstrations.

The password hashing, email flow, CSRF handling, and Flask server configuration are simplified for teaching and are not production implementations.
