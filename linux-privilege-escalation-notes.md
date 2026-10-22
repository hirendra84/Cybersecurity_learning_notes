# Linux Privilege Escalation & Enumeration — Learning Notes

> A practical reference for learning Linux system enumeration and privilege escalation in **authorized environments**, including CTFs, intentionally vulnerable virtual machines, and systems you own or have explicit permission to test.

## Table of Contents

- [1. Learning Resources](#1-learning-resources)
- [2. Linux System Enumeration](#2-linux-system-enumeration)
- [3. Kernel and Operating-System Information](#3-kernel-and-operating-system-information)
- [4. User and Group Enumeration](#4-user-and-group-enumeration)
- [5. Process and Service Enumeration](#5-process-and-service-enumeration)
- [6. Network Enumeration](#6-network-enumeration)
- [7. Password and Sensitive-File Discovery](#7-password-and-sensitive-file-discovery)
- [8. Automated Enumeration Tools](#8-automated-enumeration-tools)
- [9. File Permissions and Writable Files](#9-file-permissions-and-writable-files)
- [10. SSH Keys and Access Controls](#10-ssh-keys-and-access-controls)
- [11. Sudo Privilege Review](#11-sudo-privilege-review)
- [12. SUID and SGID Files](#12-suid-and-sgid-files)
- [13. Linux Capabilities](#13-linux-capabilities)
- [14. Scheduled Tasks and Services](#14-scheduled-tasks-and-services)
- [15. NFS Misconfiguration Checks](#15-nfs-misconfiguration-checks)
- [16. Docker and Container Permissions](#16-docker-and-container-permissions)
- [17. Web Directory and Content Discovery](#17-web-directory-and-content-discovery)
- [18. Historical Vulnerabilities and Kernel Exploits](#18-historical-vulnerabilities-and-kernel-exploits)
- [19. Practical Enumeration Checklist](#19-practical-enumeration-checklist)
- [20. Important Safety Notes](#20-important-safety-notes)

---

## 1. Learning Resources

Use these resources to understand Linux enumeration, common misconfigurations, and privilege-escalation techniques:

- [HackTricks — Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)
- [GTFOBins](https://gtfobins.github.io/) — documents how Unix binaries can be abused in misconfigured environments.
- [PEASS-ng / LinPEAS](https://github.com/peass-ng/PEASS-ng) — automated privilege-escalation enumeration scripts.
- [LinEnum](https://github.com/rebootuser/LinEnum) — Linux enumeration script.
- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) — helps identify potentially relevant kernel vulnerabilities.
- [Linux kernel documentation](https://docs.kernel.org/)
- [g0tmi1k — Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [Swissky's PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

**Learning approach:** start with manual enumeration, understand why each finding matters, and then compare your findings with automated tools. A tool's output is a lead to investigate—not proof that a system is exploitable.

## 2. Linux System Enumeration

Begin by identifying the current account, its permissions, the operating system, and the system's general configuration.

```bash
# Current username
whoami

# User ID, primary group, and supplementary groups
id

# Hostname
hostname

# Distribution and version, when available
cat /etc/os-release

# Kernel and architecture summary
uname -a

# Current working directory
pwd

# Files in the current directory, including hidden files
ls -la
```

### What to look for

- The current user's identity and group memberships.
- The operating-system distribution and version.
- The kernel version and CPU architecture.
- Files or directories that the current account can write to.
- Application configuration files, scripts, backups, and deployment artifacts that are readable by the account.

Do not assume that a particular operating-system version is vulnerable merely because it is old. Confirm the configuration and vulnerability requirements.

## 3. Kernel and Operating-System Information

Kernel information can help you determine which security updates and vulnerability checks are relevant.

```bash
# Kernel release, architecture, and build information
uname -a

# Kernel version information
cat /proc/version

# Distribution information
cat /etc/os-release

# CPU architecture and capabilities
lscpu

# Current kernel parameters
sysctl -a 2>/dev/null | less
```

### Kernel-exploit assessment

When investigating a possible kernel vulnerability:

1. Record the kernel release and distribution.
2. Identify the distribution's patch level and backported security fixes.
3. Check the vulnerability's affected versions, prerequisites, and mitigations.
4. Reproduce the finding in an isolated lab before drawing conclusions.
5. Prefer installing the vendor's security update over running an exploit.

A kernel version string alone is not sufficient to establish exploitability. Distributions sometimes backport security fixes without changing the upstream version in an obvious way.

## 4. User and Group Enumeration

```bash
# Current identity
whoami
id

# Local account database
cat /etc/passwd

# Print account names only
cut -d: -f1 /etc/passwd

# Resolve accounts using the configured name-service sources
getent passwd

# List groups
cat /etc/group
getent group

# Show the current user's groups
groups

# Show the current user's command history, if available
history
```

### Understanding `/etc/passwd`

Entries in `/etc/passwd` normally use this format:

```text
username:password_placeholder:UID:GID:GECOS:home_directory:login_shell
```

For example, a UID of `0` represents the root identity. Accounts with low UIDs are often system accounts, but UID ranges vary by distribution and configuration.

To list accounts whose configured login shell is not a common non-login shell:

```bash
awk -F: '$7 !~ /(nologin|false)$/ {print $1, $3, $6, $7}' /etc/passwd
```

This is only a rough filter; it does not prove that an account can log in interactively.

### Understanding `/etc/shadow`

```bash
# Check file metadata and permissions
ls -l /etc/shadow

# Inspect account-aging settings, where permitted
chage -l "$USER"
```

`/etc/shadow` stores password hashes and password-aging information and is normally restricted to privileged access. Do not attempt to bypass its permissions or collect credentials from systems without authorization.

### Sudo privileges

```bash
# Display commands the current user is permitted to run through sudo
sudo -l
```

Review the permitted commands, target users, environment settings, and whether a command can execute other programs or load user-controlled files. Do not assume that a listed command is exploitable without evaluating its exact configuration.

## 5. Process and Service Enumeration

```bash
# List processes with user and command details
ps aux

# Filter processes owned by root
ps aux | grep '[r]oot'

# Alternative process view
ps -ef

# Show listening TCP/UDP sockets and associated processes, if permitted
sudo ss -lntup

# Show enabled and running services on systemd systems
systemctl --type=service --state=running

# Inspect a specific service
systemctl status SERVICE_NAME
```

Replace `SERVICE_NAME` with the actual service name.

### Review for

- Services running with elevated privileges.
- Custom scripts or binaries executed by privileged services.
- Writable service configuration files.
- Credentials exposed in process arguments or configuration files.
- Unnecessary services listening on network interfaces.

A process running as root is not automatically vulnerable. Look for a demonstrable unsafe configuration or permission boundary.

## 6. Network Enumeration

```bash
# Interfaces and assigned IP addresses
ip address
ip -br address

# Routing table
ip route

# Neighbour/ARP cache
ip neigh

# Listening sockets
ss -lntup

# All sockets, where supported
ss -a

# Legacy commands; may not be installed
ifconfig
route -n
arp -a
netstat -an
```

### What the output tells you

- `ip address`: network interfaces and assigned addresses.
- `ip route`: routes and the default gateway.
- `ip neigh`: discovered neighbouring hosts and their link-layer information.
- `ss -lntup`: listening TCP/UDP sockets; process details may require elevated permissions.
- `netstat`: older networking utility; `ss` is generally preferred on modern Linux systems.

Use network information to understand the host's exposure and connectivity. Only scan or probe networks for which you have permission.

## 7. Password and Sensitive-File Discovery

Sensitive information may be exposed through configuration files, deployment scripts, application logs, backups, or environment files. Start with known application directories and files that you are authorized to inspect rather than indiscriminately reading the entire filesystem.

```bash
# Search selected configuration and application directories for password-like terms
grep -RniE 'password|passwd|secret|token|api[_-]?key' \
  /etc /opt /srv /var/www 2>/dev/null
```

This search can produce false positives and may encounter files containing sensitive information. Handle any findings securely and do not copy credentials into public reports or repositories.

### Locate potentially relevant files

```bash
# Find files named authorized_keys in accessible directories
find /home /root -type f -name authorized_keys 2>/dev/null

# Find SSH private-key filenames in common home directories
find /home /root -type f \
  \( -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' \) \
  2>/dev/null

# Search for files with a specific name under selected paths
find /etc /opt /srv /var/www -type f -iname '*config*' 2>/dev/null
```

File names alone do not prove that a file contains a usable secret. Verify ownership, permissions, purpose, and whether the secret is still valid—without attempting unauthorized access.

### `locate` and command history

```bash
# Search the locate database, if installed and up to date
locate authorized_keys 2>/dev/null | less

# Display shell history when available
history

# Inspect the current user's common Bash history file
cat ~/.bash_history 2>/dev/null
```

The `locate` database may be incomplete or outdated. History files may contain sensitive commands or tokens, so handle their contents carefully.

## 8. Automated Enumeration Tools

Automated scripts can identify configuration issues more quickly, but their results require manual verification.

| Tool | Purpose | Repository |
|---|---|---|
| LinPEAS | Broad Linux privilege-escalation enumeration | [PEASS-ng](https://github.com/peass-ng/PEASS-ng) |
| LinEnum | Linux system and privilege enumeration | [LinEnum](https://github.com/rebootuser/LinEnum) |
| Linux Exploit Suggester | Identifies potentially relevant kernel exploits from system details | [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) |

### Recommended workflow

1. Collect basic information manually.
2. Run an approved enumeration script in the lab.
3. Record findings and their supporting evidence.
4. Verify permissions and configuration manually.
5. Distinguish a confirmed weakness from a potential lead.
6. Document remediation and retest after fixes.

Only transfer and execute scripts on systems where you are authorized to do so. Review scripts before running them, particularly when they request elevated privileges.

## 9. File Permissions and Writable Files

Linux permissions are commonly represented as:

- `r` — read
- `w` — write
- `x` — execute or directory traversal
- `s` — set-user-ID or set-group-ID bit, depending on its position
- `t` — sticky bit, commonly used on shared writable directories

```bash
# Inspect permissions, ownership, and file type
ls -la
stat FILE_NAME

# Inspect important account-file permissions
ls -l /etc/passwd /etc/shadow

# Find files writable by the current user under selected locations
find /etc /opt /srv /var/www -type f -writable 2>/dev/null

# Inspect directory permissions
find /etc /opt /srv /var/www -type d -writable 2>/dev/null
```

Replace `FILE_NAME` with the file being inspected.

### Permission example

```text
-rwxr-xr-x
```

This means the owner can read, write, and execute the file; the group can read and execute it; and other users can read and execute it.

### Security lessons

- A writable script used by a privileged service can create a serious privilege boundary issue.
- A writable directory can be dangerous when a privileged process trusts files inside it.
- A file being writable does not automatically provide elevated access; execution context and how the file is used matter.
- Avoid using `chmod 777` as a troubleshooting shortcut. It grants broad permissions and can create security problems.

## 10. SSH Keys and Access Controls

SSH keys are a normal authentication mechanism. Their security depends on ownership, file permissions, server configuration, and how the key is authorized.

```bash
# Inspect SSH directories and permissions
ls -ld ~/.ssh 2>/dev/null
ls -la ~/.ssh 2>/dev/null

# Inspect public-key files
ls -l ~/.ssh/*.pub 2>/dev/null

# Check the current user's authorized public keys
cat ~/.ssh/authorized_keys 2>/dev/null

# Check SSH client configuration
cat ~/.ssh/config 2>/dev/null
```

**Important:** `authorized_keys` normally contains public keys, not private keys. A private key such as `id_rsa` or `id_ed25519` must be protected and should not be shared.

A private key's presence does not imply that it can log in as root. Authentication also depends on the target account, server configuration, key authorization, and any additional access controls. Use only keys you own or are explicitly authorized to test.

## 11. Sudo Privilege Review

`sudo` allows an administrator to grant specific users permission to run selected commands as another user, often root.

```bash
# Review the current user's sudo policy
sudo -l

# Inspect sudo configuration metadata
ls -l /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Never edit sudo policy files casually. Administrators should use `visudo` to validate configuration syntax.

### Common areas to study

- **Shell escapes:** whether a permitted program can launch another command or shell.
- **Command arguments:** whether user-controlled paths or options are trusted.
- **Environment variables:** whether the policy permits unsafe environment settings.
- **LD_PRELOAD:** whether a privileged execution path incorrectly permits a user-controlled shared library.
- **Misconfigured scripts:** whether a privileged command executes scripts or reads files that an unprivileged user can modify.

### GTFOBins

[GTFOBins](https://gtfobins.github.io/) documents legitimate Unix binaries that can become security risks when their execution permissions or sudo rules are overly broad. Use it to understand the underlying mechanism in a lab and to identify safer configurations.

Do not assume that a command listed by GTFOBins will work on every system. The exact binary, version, sudo policy, environment, and security controls matter.

### Historical sudo vulnerabilities

Examples worth studying include:

- **CVE-2019-14287:** a sudo policy bypass involving specific user-ID handling and affected configurations.
- **CVE-2019-18634:** a sudo `pwfeedback` buffer-overflow vulnerability affecting specific versions and configurations.

These are historical examples, not universal privilege-escalation commands. Check vendor advisories and installed package versions, and apply supported security updates.

## 12. SUID and SGID Files

### What do SUID and SGID mean?

- **SUID (set-user-ID):** for applicable executable files, the process can run with the file owner's effective user ID.
- **SGID (set-group-ID):** for applicable executable files, the process can run with the file's effective group ID. On directories, SGID commonly causes new entries to inherit the directory's group.

The `s` character in a permission listing can indicate one of these special bits. Its meaning depends on whether it appears in the owner-execute or group-execute position.

```bash
# Find SUID files
find / -type f -perm -4000 -print 2>/dev/null

# Find SGID files
find / -type f -perm -2000 -print 2>/dev/null

# Inspect a particular file
ls -l /path/to/file
stat /path/to/file
```

### How to assess a finding

1. Identify the file and its owner.
2. Determine whether it is a standard system binary or a custom program.
3. Check its version, provenance, and expected behaviour.
4. Investigate whether it processes untrusted input or relies on writable files.
5. Compare the configuration with vendor guidance and GTFOBins documentation.

SUID does not automatically mean a file is vulnerable. Avoid changing permissions on system files during testing; use an isolated lab for controlled experiments.

## 13. Linux Capabilities

Linux capabilities divide certain root-level privileges into individual permissions. A binary may have a capability even when it is not SUID.

```bash
# List file capabilities, if getcap is installed
getcap -r / 2>/dev/null

# Inspect the current process's capabilities
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)' /proc/self/status
```

When reviewing a capability:

- Identify the exact capability and the file to which it applies.
- Determine why the application requires it.
- Check whether untrusted users can invoke or influence the program.
- Verify whether the capability is broader than necessary.
- Remove unnecessary capabilities through an approved administrative change.

Capabilities such as `cap_setuid`, `cap_dac_override`, and `cap_net_admin` have different implications. A capability alone does not prove exploitability; the program's behaviour and execution context are critical.

## 14. Scheduled Tasks and Services

Scheduled jobs may run through cron or systemd timers. Security issues can arise if a privileged job executes a script or reads a configuration file that an unprivileged user can modify.

```bash
# Current user's scheduled tasks
crontab -l 2>/dev/null

# System cron configuration
ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly \
  /etc/cron.monthly /etc/cron.weekly 2>/dev/null

# Main cron configuration
cat /etc/crontab 2>/dev/null

# List systemd timers
systemctl list-timers --all 2>/dev/null

# Inspect a specific timer or service
systemctl cat UNIT_NAME
systemctl status UNIT_NAME
```

Replace `UNIT_NAME` with the actual unit name.

Check whether the scheduled command, its script, its parent directories, or any configuration it trusts are writable by an unprivileged account. Also inspect the command's execution environment and absolute paths.

## 15. NFS Misconfiguration Checks

Network File System (NFS) allows directories to be shared between systems. Incorrect export options or permissions can expose data or create unexpected access paths.

```bash
# Display NFS mounts on the current system
findmnt -t nfs,nfs4

# Show mounted filesystems
mount

# Inspect NFS exports on a system you administer
cat /etc/exports 2>/dev/null

# If the NFS utilities are installed, list exports from an authorized server
showmount -e SERVER_IP
```

Replace `SERVER_IP` with the address of a server you are authorized to assess.

Review export restrictions, client access, filesystem ownership, and whether `root_squash` or other appropriate safeguards are enabled. Do not attempt to access or modify shares without permission.

## 16. Docker and Container Permissions

Container access can have significant security implications, particularly when a user can control a privileged container runtime or start containers with host-level access.

```bash
# Check whether Docker is installed and available
docker --version

# List the current user's groups
id

# Check whether the Docker service is active
systemctl status docker 2>/dev/null

# List running containers, if authorized
docker ps

# List local images, if authorized
docker images
```

### Review points

- Is the user a member of the `docker` group?
- Can untrusted users access the Docker socket?
- Are containers unnecessarily privileged?
- Are host directories mounted into containers with write access?
- Are sensitive host paths, credentials, or devices exposed?
- Are container images and runtime components patched?

Membership in the Docker group can grant control over the Docker daemon and may effectively confer root-equivalent power on the host, depending on the configuration. Treat access to the daemon socket as highly privileged.

## 17. Web Directory and Content Discovery

Directory and content discovery can help assess a web application in an authorized lab. It is distinct from Linux privilege escalation, but it can provide context about deployed applications and their configuration.

### Dirsearch

[Dirsearch](https://github.com/maurosoria/dirsearch) is a web-path discovery tool.

```bash
# Example for an authorized test target
python3 dirsearch.py -u https://TARGET.example -e php,html,txt

# Show help for the installed version and available options
python3 dirsearch.py --help
```

Replace the example target with a system you own or have permission to test. Use the installed version's help output to confirm the available options. Avoid aggressive scans against production systems without an approved scope and rate limit.

HTTP status codes such as `200`, `301`, `403`, and `404` require context; they do not independently establish that a resource is sensitive or vulnerable.

## 18. Historical Vulnerabilities and Kernel Exploits

Kernel exploits take advantage of flaws in the operating system kernel. They can be disruptive, crash a machine, corrupt data, or compromise the host.

### Safe assessment workflow

1. Collect `uname -a`, `/etc/os-release`, and relevant package-version information.
2. Identify a candidate CVE and confirm its affected products and versions.
3. Check vendor advisories for backported fixes and configuration prerequisites.
4. Search trusted vulnerability databases and review the exploit's source code.
5. Reproduce only in an isolated, disposable lab.
6. Record the evidence and recommend a patch or configuration fix.

### Dirty COW

**Dirty COW (CVE-2016-5195)** was a historical Linux kernel race-condition vulnerability that could allow local privilege escalation on affected systems. It has been patched in supported distributions, though obsolete systems may remain exposed.

Do not assume a system is vulnerable from its kernel version alone. Confirm vendor patch status and test safely in a controlled environment.

### Exploit collections

- [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester) — candidate vulnerability identification.
- [Exploit Database](https://www.exploit-db.com/) — public vulnerability and exploit references.
- [NVD](https://nvd.nist.gov/) — CVE information and vulnerability records.
- [Linux kernel documentation](https://docs.kernel.org/) — kernel documentation.

An exploit collection is a research reference, not a recommendation to execute arbitrary code. Validate provenance, affected versions, and safety before using any proof of concept.

## 19. Practical Enumeration Checklist

Use this checklist when working through a Linux lab.

### System
- [ ] Identify the current user and groups.
- [ ] Record the hostname, distribution, kernel, and architecture.
- [ ] Check the current directory and accessible files.

### Users and privileges
- [ ] Review `/etc/passwd` and relevant group memberships.
- [ ] Run `sudo -l` if permitted.
- [ ] Check for unnecessary administrative privileges.

### Processes and networking
- [ ] Review running processes and services.
- [ ] Identify listening sockets and network interfaces.
- [ ] Review routes and mounted filesystems.

### Files and scheduled tasks
- [ ] Inspect relevant file ownership and permissions.
- [ ] Check SUID/SGID files and Linux capabilities.
- [ ] Review cron jobs and systemd timers.
- [ ] Check application configuration and secrets within the authorized scope.

### Containers and shared resources
- [ ] Review Docker access and container configuration.
- [ ] Check NFS mounts and export policies where applicable.
- [ ] Assess service scripts and configuration for unsafe write permissions.

### Verification and reporting
- [ ] Verify each suspected issue manually.
- [ ] Distinguish confirmed vulnerabilities from unverified leads.
- [ ] Record impact, evidence, and remediation.
- [ ] Re-test after the fix.

## 20. Important Safety Notes

- Perform testing only on systems you own or are explicitly authorized to assess.
- Use isolated VMs or CTF environments for exploit development.
- Do not collect, publish, or reuse credentials belonging to other people.
- Avoid running unknown scripts or exploits with `sudo` or root privileges.
- Do not use broad permission changes such as `chmod 777` as a shortcut.
- Prefer supported security updates and least-privilege configuration over exploit-based testing.
- Redact secrets, private keys, tokens, internal IP details, and personal data from public reports.

---

## Quick Reference: Common Commands

```bash
# Identity
whoami
id
groups

# Operating system
uname -a
cat /etc/os-release
cat /proc/version
lscpu

# Users and groups
getent passwd
getent group
cut -d: -f1 /etc/passwd

# Sudo policy
sudo -l

# Processes and services
ps aux
ps -ef
systemctl --type=service --state=running

# Network
ip -br address
ip route
ip neigh
ss -lntup

# Files and permissions
ls -la
stat FILE_NAME
find / -type f -perm -4000 -print 2>/dev/null
find / -type f -perm -2000 -print 2>/dev/null
getcap -r / 2>/dev/null

# Scheduled tasks
crontab -l 2>/dev/null
systemctl list-timers --all

# Mounts
findmnt
findmnt -t nfs,nfs4
```

**Remember:** enumeration is about understanding the system and proving a security finding—not simply collecting commands or running every available exploit.
