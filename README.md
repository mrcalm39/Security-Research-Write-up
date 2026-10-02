# Session Persistence After Password Reset — Security Lab

A deliberately vulnerable web application demonstrating a **session invalidation vulnerability following password reset**.

This lab is designed for cybersecurity students, penetration testers, and security researchers who want to understand how an authenticated session can remain valid after an account's password has been changed.

> ⚠️ **Educational Use Only**
>
> This application is intentionally vulnerable. Run it only on your own computer, inside a lab environment, or on infrastructure where you have explicit authorization.
>
> Do not deploy this vulnerable version to a public-facing server.

---

# Installation

The easiest way to run this lab is with Docker.

The instructions below assume you are using Windows, Linux, or macOS and have Git and Docker installed.

---

## 🚀 How to Run this Practical Lab Locally

You can launch this fully functional application environment on your local machine using **Docker** to see the flaw in action.

### Prerequisites
Make sure you have [Docker Desktop](https://docker.com) installed and running on your machine.

### 1. Clone the Repository
Open your terminal or command prompt and clone this repository to your local machine:
```bash
git clone https://github.com/mrcalm39/session-security-lab.git
```

### 2. Navigate to the Project Directory
Change your terminal directory into the folder containing the lab files:
```bash
cd session-security-lab
```

### 3. Build the Lab Container
Build the Docker image using the customized **joeseclab** tag:
```bash
docker build -t joeseclab .
```
### 4. 

### 5. Start the Lab Environment
Run the container to expose the vulnerable application locally:
```bash
docker run -p 5000:5000 joeseclab
```

### 6. Access the Portal
Open your web browser and navigate to:
```
http://localhost:5000



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
