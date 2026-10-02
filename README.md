# PHPSESSID Session Invalidation Lab

A Dockerized web security lab demonstrating improper session invalidation after a password reset.

The lab reproduces a session-management vulnerability where an existing authenticated session remains valid after the account password has been changed.

The application provides two modes:

- `vulnerable` — demonstrates the insecure behavior
- `fixed` — demonstrates the security fix

The lab is intended for authorized security research, application-security training, and portfolio demonstrations.

---

## 🚀 How to Run this Practical Lab Locally

You can launch this fully functional application environment on your local machine using **Docker** to see the flaw in action.

### Prerequisites
Make sure you have [Docker Desktop](https://docker.com) installed and running on your machine.

### 1. Clone the Repository
Open your terminal or command prompt and clone this repository to your local machine:
```bash
git clone https://github.com/mrcalm39/Security-Research-Write-up.git
```

### 2. Navigate to the Project Directory
Change your terminal directory into the folder containing the lab files:
```bash
cd session-reset-lab
```

### 3. Build the Lab Container
Build the Docker image using the customized **joeseclab** tag:
```bash
docker build -t session-reset-lab .
```

### 4. Run Fixed Mode
Stop and remove the vulnerable container:
```bash
docker rm -f session-reset-lab
```

### 4. Run the Vulnerable Mode
```bash
docker run --name session-reset-lab \
  -p 5000:5000 \
  -e LAB_MODE=vulnerable \
  session-reset-lab
```

### 5. Access the Portal
Open your web browser and navigate to:
```
http://localhost:5000
```


## Vulnerability Overview

The vulnerability occurs when a user changes their password but previously issued authenticated sessions are not invalidated.

For example:

```text
Victim logs in
      |
      v
PHPSESSID = SESSION_A
      |
      v
Existing authenticated session
      |
      +-----------------------------+
      |                             |
      | Password is changed         |
      |                             |
      v                             |
New password is created             |
                                    |
                                    v
                         SESSION_A remains valid
                                    |
                                    v
                         Old session is still
                         authenticated
                                    |
                                    v
                         Authorized actions
                         can still be performed
