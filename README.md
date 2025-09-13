# secure_audit_logger

**secure_audit_logger** is a hardened daemon designed for secure collection and preservation of command histories or audit logs in **multi-user Linux/FreeBSD environments** (hundreds to thousands of users).  
It provides **tamper-resistant logging** and integrates well with external tools such as `logrotate` or journald.

---

## Features

- **Daemonized Operation**  
  - Runs as a background service (or foreground with `--no-daemon`).
  - Proper PID file locking (`/var/run/secure_audit_logger.pid`).

- **Secure Logging**  
  - Logs are written with `O_APPEND | O_NOFOLLOW` to prevent tampering.  
  - Strict `umask(077)` applied.  
  - Enforces ownership and permissions of log directory (`root` or `root:logger`).

- **Privilege Dropping**  
  - Runs privileged operations as `root`, then immediately drops to `nobody:logger`.

- **Audit Metadata**  
  Each log entry includes:
  - Timestamp
  - Hostname
  - PID
  - Real UID/GID and usernames
  - TTY (including SSH_TTY if applicable)
  - SSH connection details (`SSH_CONNECTION`)

- **Rotation Support**  
  - `SIGHUP` to re-open log file (for use with `logrotate`).
  - Simple daily rotation mode (`audit-YYYYMMDD.log`).

- **Reliability**  
  - Periodic `fdatasync()` (every 100 lines).  
  - Heartbeat log (every hour) to confirm liveness.

- **Optional Journald Replication**  
  - Configurable dual-logging to syslog/journald.

---

## Requirements

- Linux or FreeBSD
- GCC / Clang
- Root privileges for installation and execution

---

## Build

```sh
gcc -O2 -Wall -o secure_audit_logger secure_audit_logger.c
```
## Installation

 - Copy the binary to /usr/local/secureaudit/bin/secure_audit_logger
 - Create configuration file /etc/secure_audit_logger.conf
 - Create secure log directory:

```sh
mkdir -p /var/log/secure_audit
groupadd logger
chown root:logger /var/log/secure_audit
chmod 0770 /var/log/secure_audit
```
## Ensure config file is owned by root:
```sh
chown root:root /etc/secure_audit_logger.conf
chmod 0600 /etc/secure_audit_logger.conf
```

## Configuration Example
/etc/secure_audit_logger.conf
```sh
# Log directory (must exist, root-owned, 0700 or 0770)
log_directory=/var/log/secure_audit

# Rotation type: none | daily
log_rotation_type=daily

# Journald replication: yes | no
journal_replication=yes
```

## Usage
Run manually in foreground (debug):
```sh
/usr/local/sbin/secure_audit_logger --no-daemon
```
# Run as daemon (default):
```sh
/usr/local/sbin/secure_audit_logger
```
# Stop gracefully with:
```sh
kill -TERM $(cat /var/run/secure_audit_logger.pid)
```

## Systemd Unit Example
/etc/systemd/system/secure_audit_logger.service

```bash
[Unit]
Description=Secure Audit Logger Daemon
After=network.target

[Service]
ExecStart=/usr/local/sbin/secure_audit_logger
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
Reload and enable:
```

```sh
systemctl daemon-reload
systemctl enable secure_audit_logger
systemctl start secure_audit_logger
```

## Security Notes
- The log directory must be root-owned and not world-writable.
- Config file must be 0600 and root-owned.
- Tampered log files (wrong owner/permissions) cause the daemon to abort.
- Runs as nobody:logger after setup to minimize privilege exposure.
- Core dumps are disabled (prctl(PR_SET_DUMPABLE, 0)).

## License
MIT License
