# SQL Injection Authentication Bypass Demonstration & Mitigation

**Student name:** MALIK TOUQEER  
**Roll number:** IIB2024015  
**Course:** IT-30001 Web Server Security  
**Variant:** SQL Injection — Authentication Bypass

## Overview

A simple Campus Portal with a login page, a protected home page, profile information, a notice board and logout. The profile and notices are fetched from SQLite. The login form supports vulnerable and secured implementations to demonstrate SQL injection and its mitigation.

## Prerequisites

- Node.js 24 or higher
- Git, to clone the repository

No external npm packages or separate SQLite installation are required.

## Installation & Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
   ```
2. Open the application directory:
   ```bash
   cd YOUR_REPOSITORY/campus-portal
   ```
   If the application files are at the repository root, use `cd YOUR_REPOSITORY` instead.
3. Start the server:
   ```bash
   node server.js
   ```
   Alternatively, run `npm start`.
4. Open **http://localhost:3000**.

The database is created automatically. New demo accounts are also added when an existing database is opened; existing accounts are preserved. Keep the terminal running; press Ctrl+C to stop.

## Demo Accounts

| Username | Password | Name | Role |
| --- | --- | --- | --- |
| admin | Admin@123 | Touqeer | Administrator |
| student | Student@123 | Ayaan Ahmad | Student |
| ahmad | Ahmad@123 | Ahmad Khan | Student |
| sara | Sara@123 | Sara Ali | Student |
| hamza | Hamza@123 | Hamza Mir | Student |
| zoya | Zoya@123 | Zoya Shah | Student |
| bilal | Bilal@123 | Bilal Ahmad | Student |

All account details and notices are demonstration data, not official institute records.

## Demonstration

### Normal Login

1. Select **Vulnerable** on the login page.
2. Enter `admin` and `Admin@123`, then click **Sign in**.
3. The browser redirects to `/home`, displaying the administrator's profile and notices from SQLite.
4. Click **Logout**. The session is invalidated and the browser returns to login.
5. Try `admin` with an incorrect password. The application stays on login and shows **Invalid username or password.**

### Authentication Bypass

1. Select **Vulnerable**.
2. Enter username `admin' -- ` (include a trailing space).
3. Enter password `anything` and click **Sign in**.
4. The browser redirects to the administrator's home page without the correct password.
5. Click **Logout**.

The vulnerable query is built by concatenating input:

```js
const sql = "SELECT id FROM users WHERE username = '" + username +
  "' AND password = '" + password + "'";
return db.prepare(sql).get();
```

With the payload, SQLite executes this single-line query:

```sql
SELECT id FROM users WHERE username = 'admin' -- ' AND password = 'anything'
```

The quote closes the username string. The comment marker removes the password condition from the rest of the line. This bypasses authentication; it does not recover the password.

### Mitigation

1. Select **Secured**.
2. Enter the identical username `admin' -- ` and password `anything`.
3. Click **Sign in**. The application remains on login and shows **Invalid username or password.**
4. Capture this blocked attempt as mitigation evidence.
5. Enter the valid admin credentials to verify normal login still works.

The fixed query binds values separately:

```js
const sql = 'SELECT id FROM users WHERE username = ? AND password = ?';
return db.prepare(sql).get(username, password);
```

The entire payload is treated as a literal username. It cannot alter the SQL structure. Calling `prepare()` on concatenated SQL alone is not a fix.

## Files to Explain

| File | Purpose |
| --- | --- |
| database.js | Creates the database and contains vulnerable/fixed authentication, profile and notice queries |
| server.js | Processes login, redirects to home, manages sessions, renders database information and logs out |
| public/index.html | Login form with Vulnerable / Secured selector |
| public/home.html | Home page template containing profile and notice board |
| public/login.js | Displays generic errors and preserves mode selection after failed login |
| public/style.css | Login and home page styles |
| test/portal.test.js | Integration tests using a real Node server and SQLite |

## Authentication Flow

Browser submits POST /login → server runs the selected query → server creates an HttpOnly session cookie → browser redirects to GET /home → server reads the profile and notices from SQLite.

Sessions store only the user ID and expiry. Home requests look up the current profile in the database. Visiting `/home` without a session redirects to login. POST /logout deletes the session and expires the cookie. Sessions expire after 15 minutes and are cleared on server restart. Role is displayed from the database; this version has no role-specific write actions.

## Other Mitigations

- **Safe ORM use:** Use methods that parameterise values. Concatenated raw SQL can reintroduce injection.
- **Allow-list validation:** Validate expected formats; use a fixed allow-list for dynamic identifiers such as column names, which value placeholders cannot bind.
- **Least privilege:** Restrict database access to limit damage. SQLite uses operating-system file permissions instead of normal database users and GRANT permissions.
- **Safe errors:** Use generic messages instead of leaking internal errors. This limits information disclosure but does not remove the injection flaw.

These support parameterised queries, which are the implemented SQL injection fix.

## Tests

```bash
npm test
```

Tests check valid/invalid logins, bypass before mitigation, the same payload failing after mitigation, protected home access, separate user profiles, fresh database reads, safe HTML output, logout, redirects and invalid requests.

## Ownership

| Member name | Roll number | Category | Variant |
| --- | --- | --- | --- |
| YOUR_NAME | YOUR_ROLL_NUMBER | SQL Injection | Authentication Bypass |

## Local Demonstration

Run only locally and use fictional credentials. The server binds to 127.0.0.1. Data is stored in `data/portal.sqlite`; the directory is excluded from Git. To reset demo data, stop the server, delete the data directory and restart.

Plaintext passwords simplify the comparison between the two SQL implementations. Production authentication requires salted password hashing and additional controls. Both modes share the same input rules; the secured mode blocks injection through bound query values, rather than an attack-string blacklist.
