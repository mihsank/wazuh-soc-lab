# Home SOC Lab with Wazuh

> Hands-on SOC lab built as part of the MyDFIR Wazuh SOC Analyst Challenge.
> Goal: deploy a SIEM/XDR, collect endpoint telemetry, detect attacker activity, and investigate an incident end to end.

**Tools:** Wazuh 4.14 · Sysmon · Sysmon for Linux · VMware Workstation Pro · Windows 10 · Ubuntu 26.04
**Date:** 11/2026

## Contents

1. [Lab Architecture](#1-lab-architecture)
2. [Deploying the Wazuh Server](#2-deploying-the-wazuh-server)
3. [Connecting Agents + Sysmon](#3-connecting-agents--sysmon)
4. [Generating and Reading Telemetry](#4-generating-and-reading-telemetry)
5. [SOC Dashboard](#5-soc-dashboard)
6. [File Integrity Monitoring + Custom Rules](#6-file-integrity-monitoring--custom-rules)
7. [Active Response](#7-active-response)
8. [Investigation](#8-investigation)
9. [Lessons Learned](#9-lessons-learned)

## Repository structure

```
├── README.md                 writeup
├── configs/
│   ├── wazuh-server/         local_rules.xml, ossec.conf and filebeat.yml changes
│   ├── windows-agent/        Sysmon forwarding, FIM path
│   └── ubuntu-agent/         FIM path
├── diagrams/                 architecture.drawio
└── images/                   screenshots
```

---

## 1. Lab Architecture

![Lab architecture: Wazuh server, Windows and Ubuntu endpoints on a VMware NAT network, with ports and data flows](images/00-architecture.png)

*Editable source: [`diagrams/architecture.drawio`](diagrams/architecture.drawio) (open in [draw.io](https://app.diagrams.net)).*

| Hostname | Role | OS / Hosting | IP |
|---|---|---|---|
| `wazuh` | Wazuh server: manager, indexer, dashboard | Ubuntu 26.04.1 LTS, local VM (VMware) | 192.168.15.128 |
| `windows` (agent: `windows-agent`) | Monitored endpoint: Wazuh agent + Sysmon | Windows 10 Pro 22H2, local VM | 192.168.15.131 |
| `ubuntu` (agent: `ubuntu-agent`) | Monitored endpoint: Wazuh agent + Sysmon for Linux | Ubuntu 26.04.1 LTS, local VM | 192.168.15.129 |

**Wazuh version:** 4.14.8 (all-in-one, single node `node01`)

> **Note:** The challenge video used Ubuntu 24.04 for compatibility. This lab runs both Linux VMs (Wazuh server and Ubuntu endpoint) on **Ubuntu 26.04.1 LTS**; any compatibility issues met are documented in the sections below.

---

## 2. Deploying the Wazuh Server

**VM setup.** Ubuntu Server VM on VMware Workstation Pro (NAT network), hostname `wazuh`, IP `192.168.15.128`. OpenSSH was installed so the VM could be managed over SSH from the host PC. The system was updated and then upgraded to Ubuntu 26.04.1 LTS with `do-release-upgrade` before Wazuh was installed.

```bash
sudo apt-get update && sudo apt-get upgrade -y
sudo do-release-upgrade
```

**Wazuh installation.** Wazuh 4.14 was installed in all-in-one mode (manager, indexer and dashboard on one node) with the official installation assistant:

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

The installer prints the `admin` credentials at the end. If they are lost, they can be recovered from the installation files (credentials are stored in a password manager, not in this repository):

```bash
sudo tar -xf wazuh-install-files.tar
sudo cat wazuh-install-files/wazuh-passwords.txt
```

The dashboard is then reachable at `https://192.168.15.128` (port 443).

**Enabling archives.** By default, Wazuh only indexes events that match a rule (`wazuh-alerts-*`). Events that trigger no alert, such as a normal successful logon, are not searchable. For investigations I want to see everything, so I enabled archives:

1. `/var/ossec/etc/ossec.conf` on the server: set `logall` and `logall_json` to `yes`, then `sudo systemctl restart wazuh-manager`.

```xml
<global>
  <logall>yes</logall>
  <logall_json>yes</logall_json>
</global>
```

2. `/etc/filebeat/filebeat.yml`: in the Wazuh module, set `archives.enabled` to `true`, then `sudo systemctl restart filebeat`.

```yaml
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: true
```

3. Dashboard Management → Index patterns → created an index pattern for `wazuh-archives-*` with `timestamp` as the time field.

**Snapshot.** After the server was configured, I took a VMware snapshot as a known-good restore point.

> **Rule learned:** every change to `ossec.conf` needs a restart of the `wazuh-manager` service (on endpoints: the Wazuh agent service).

**Wazuh dashboard login (HTTPS, port 443):**

![Wazuh dashboard login page](images/01-dashboard-login.png)

**Dashboard overview after deployment:**

![Wazuh dashboard overview with agent summary and alert severity counts](images/02-dashboard-overview.png)

---

## 3. Connecting Agents + Sysmon

**Endpoint VMs.** Two more VMs on the same NAT network:

- `ubuntu`: Ubuntu 26.04.1 LTS, `192.168.15.129`, managed over SSH
- `windows`: Windows 10 Pro, `192.168.15.131`, Remote Desktop enabled for RDP access

![Windows endpoint system information (Windows 10 Pro 19045, VMware)](images/04-windows-system-info.png)

**Agent enrollment.** In the dashboard: *Deploy new agent* → select the OS (Windows MSI / Linux DEB amd64) → enter the server address `192.168.15.128` → give the agent a name (`windows-agent`, `ubuntu-agent`). The generated commands were run **on the endpoints** (PowerShell as Administrator on Windows, a terminal on Ubuntu), not on the server. Each agent showed *Never connected* first and *Active* after about a minute.

> If an agent sends no events, check that it can reach the manager on **1514/tcp** (events) and **1515/tcp** (enrollment). Network rules blocking these ports are the most common cause.

**Sysmon on Windows.** Windows Security logs alone miss many details, such as full command lines, parent processes, hashes and network connections. Sysmon adds them.

1. Downloaded Sysmon from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and the Olaf Hartong **sysmon-modular** configuration (`sysmonconfig.xml`).
2. Installed it with the configuration:

```powershell
.\Sysmon.exe -i .\sysmonconfig.xml
```

3. Installing Sysmon is not enough: the Wazuh agent must be told to read the Sysmon event channel. I added this block to `C:\Program Files (x86)\ossec-agent\ossec.conf` and restarted the Wazuh agent service:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

**Sysmon for Linux on Ubuntu.** Installed from the Microsoft package repository ([install guide](https://github.com/microsoft/Sysmon-Linux/blob/main/INSTALL.md)) and started with Microsoft's MSTIC `collect-all.xml` configuration. Sysmon for Linux writes its events to `/var/log/syslog`, which the Wazuh agent forwards to the manager.

```bash
wget -q https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt-get update
sudo apt-get install sysmonforlinux
wget https://raw.githubusercontent.com/microsoft/MSTIC-Sysmon/refs/heads/main/linux/configs/collect-all.xml
sudo sysmon -i collect-all.xml
```

**Both agents enrolled and active:**

![Wazuh endpoints page showing windows-agent and ubuntu-agent as active](images/03-agents-active.png)

---

## 4. Generating and Reading Telemetry

In this part I played the **attacker** on both endpoints, then switched sides and found every action in Wazuh as the **analyst**. I searched the `wazuh-archives*` index (all events) and `wazuh-alerts-*` (only events that matched a rule).

> **Timezone note:** the dashboard shows times in the browser's local time (UTC+1). Raw Linux log lines (`full_log`) are in UTC. Example: the SSH login at `20:09:18` in the raw log appears as `21:09:18` in the dashboard. In an investigation, always normalize timestamps to one timezone first.

### 4.1 Windows: account manipulation

Commands run in an elevated Command Prompt on `windows` (test passwords replaced with `<password>`):

```cmd
whoami
ipconfig /all
net user
net localgroup administrators
net user guest /active:yes
net user guest <password>
net user student1 <password> /add
net localgroup administrators student1 /add
net localgroup administrators
net user student1 /delete
```

![Commands run on the Windows endpoint](images/05-win-commands.png)

**What I found in Wazuh**

| Action | Event ID | How to read the log |
|---|---|---|
| Account created | **4720** | *Subject* = who did it (`windows`, RID 1001). *New Account* = the created account (`student1`, RID 1004). |
| Added to Administrators | **4732** | *Member Account Name* is only `-`. The member must be identified by its **SID**. Group SID `S-1-5-32-544` = built-in Administrators. |
| Account deleted | **4726** | *Subject* deleted the *Target Account* with RID 1004. |
| Successful logon | **4624** | *Subject* `S-1-5-18` / `DESKTOP-PPHT146$` is **SYSTEM** (the process that handled the logon). The user who logged on is in the *New Logon* section. Logon type 2 = interactive (VMware console). |

![4720: user account created](images/06-win-4720-created.png)

![4732: member added to the Administrators group](images/07-win-4732-added.png)

**Resolving a member without a name.** In 4732 the member name is `-`, so I copied the member SID and searched for it in the archives. A 4726 event with the same SID showed `targetUserName: student1`.

![4732 detail: member account name is empty, only the SID is shown](images/08-win-4732-member-sid.png)

![Searching the SID in the archives resolves it to student1](images/09-win-sid-resolved-student1.png)

![4726: user account deleted](images/10-win-4726-deleted.png)

![4624: successful logon, Subject is SYSTEM](images/11-win-4624-logon.png)

### 4.2 Linux: SSH brute force and session tracking

From `windows` (192.168.15.131), I attacked `ubuntu` (192.168.15.129):

1. Three failed SSH logins with a non-existent user: `ssh fakeuser@192.168.15.129`
2. A successful login with a valid account: `ssh ubuntu@192.168.15.129`
3. Discovery and staging commands in that session:

```bash
ip a
whoami
cat /etc/passwd
cat /etc/passwd > /tmp/loot.txt
cd /tmp && ls
```

![Three failed SSH logins as fakeuser from the Windows host](images/12-ssh-bruteforce-client.png)

![Successful SSH login as ubuntu](images/13-ssh-login-client.png)

**What I found in Wazuh**

| Raw log line (UTC) | Meaning | Wazuh rule / MITRE ATT&CK |
|---|---|---|
| `Connection reset by invalid user fakeuser 192.168.15.131 port 50030` | Login attempt with a user that does not exist | *sshd: Attempt to login using a non-existent user* · T1110 Password Guessing |
| `PAM: User login failed` | Wrong credentials | Password Guessing · Credential Access |
| `User missed the password more than one time` | Repeated failures from one source | Brute Force · Credential Access |
| `Accepted password for ubuntu from 192.168.15.131 port 50031 ssh2` | **Successful login from the same IP that just failed** | *sshd: authentication success* · T1078 Valid Accounts, T1021 Remote Services |
| `Started session-5.scope - Session 5 of User ubuntu` | Login session 5 opened | systemd |
| `pam_unix(sshd:session): session closed for user ubuntu` | Session ended | *PAM: Login session closed* |

![sshd events with rule descriptions and MITRE tactics](images/14-sshd-alerts-overview.png)

![Raw log: connection reset by invalid user fakeuser](images/15-sshd-invalid-user-log.png)

![Raw log: accepted password for ubuntu from 192.168.15.131](images/16-sshd-accepted-password.png)

![Authentication success mapped to MITRE ATT&CK](images/17-sshd-auth-success-mitre.png)

**Following one session from login to logout.** Three values connect all events of the same SSH session:

| Link | Value in this lab | Where it appears |
|---|---|---|
| Session ID | `5` | systemd *Session 5 of User ubuntu* and Sysmon `TerminalSessionId` |
| sshd process ID | `3328` | `sshd-session[3328]` in both *Accepted password* and *session closed* |
| User | `ubuntu` | all events |

Sysmon for Linux recorded every command with its full command line, parent process and session. Example: `ip a`, run from `/usr/bin/bash` by user `ubuntu`, in `TerminalSessionId 5`:

![Sysmon for Linux Event ID 1: process creation for "ip a" in session 5](images/18-sysmon-linux-ip-a.png)

![systemd: session 5 started for user ubuntu](images/19-session-started.png)

![PAM: session closed for user ubuntu](images/20-session-closed.png)

**Session timeline (UTC):** 20:09:01 failed logins from .131 → 20:09:18 accepted login (session 5) → 20:10:08 `ip a` → … → 21:26:03 session closed.

### 4.3 MITRE ATT&CK mapping of the simulated activity

| Activity | Tactic | Technique |
|---|---|---|
| `whoami`, `net user`, `net localgroup`, `cat /etc/passwd` | Discovery (TA0007) | T1033 System Owner/User Discovery · T1087.001 Account Discovery: Local Account |
| `ipconfig /all`, `ip a` | Discovery (TA0007) | T1016 System Network Configuration Discovery |
| Enable the built-in Guest account | Persistence (TA0003) · Privilege Escalation (TA0004) · Defense Evasion (TA0005) · Initial Access (TA0001) | T1078.001 Valid Accounts: Default Accounts |
| `net user student1 /add` | Persistence (TA0003) | T1136.001 Create Account: Local Account |
| Add `student1` to Administrators | Persistence (TA0003) · Privilege Escalation (TA0004) | T1098 Account Manipulation |
| SSH logins as `fakeuser` | Credential Access (TA0006) | T1110.001 Brute Force: Password Guessing |
| SSH login as `ubuntu` from `windows` | Lateral Movement (TA0008) | T1021.004 Remote Services: SSH |
| `cat /etc/passwd > /tmp/loot.txt` | Collection (TA0009) | T1074.001 Data Staged: Local Data Staging |

> **Tactic** = the attacker's goal (the *why*). **Technique** = how the goal is reached (the *how*). One technique can serve several tactics: a valid account, for example, gives both access and persistence.

### 4.4 Event ID cheat sheet

**Windows Security log: the IDs a SOC analyst sees most often** (⭐ = generated in this lab)

| Event ID | Meaning | Why it matters |
|---|---|---|
| ⭐ **4624** | Successful logon | Who logged on, from where, how (logon type) |
| **4625** | Failed logon | Brute force, password spraying. Check `Status`/`SubStatus`: `0xC0000064` user does not exist, `0xC000006A` wrong password |
| **4634 / 4647** | Logoff | End of a session (with 4624: session duration) |
| **4648** | Logon with explicit credentials | `runas`, lateral movement |
| **4672** | Special privileges assigned to a new logon | Admin-level logon |
| **4688** | New process created | Command execution (needs process auditing) |
| **4697 / 7045** | Service installed | Persistence, remote execution (e.g. PsExec) |
| **4698** | Scheduled task created | Persistence |
| **4719** | Audit policy changed | Defense evasion |
| ⭐ **4720** | User account created | Persistence |
| ⭐ **4722** | User account enabled | e.g. Guest account enabled |
| **4723 / 4724** | Password change / reset attempt | Account takeover |
| **4725** | User account disabled | |
| ⭐ **4726** | User account deleted | Covering tracks |
| **4728 / 4756** | Member added to a global / universal group | Domain privilege escalation |
| ⭐ **4732** | Member added to a local group | Local admin rights |
| **4733** | Member removed from a local group | |
| **4738** | User account changed | |
| **4740** | Account locked out | Brute force indicator |
| **4768 / 4769** | Kerberos TGT / service ticket requested | Kerberoasting, domain logons |
| **4771 / 4776** | Kerberos pre-auth failed / NTLM credential validation | Password attacks in a domain |
| **1102** | Security log cleared | **Always suspicious** (anti-forensics) |
| **4104** | PowerShell script block logged (PowerShell/Operational) | Malicious scripts |

**Logon types (4624 / 4625)**

| Type | Meaning |
|---|---|
| **2** | Interactive: at the keyboard or VM console |
| **3** | Network: SMB, file shares, PsExec |
| **4** | Batch: scheduled task |
| **5** | Service |
| **7** | Unlock (also RDP reconnect) |
| **8** | Network clear text: credentials sent in clear text |
| **9** | New credentials: `runas /netonly` |
| **10** | RemoteInteractive: **RDP** |
| **11** | Cached credentials: offline domain logon |

**Sysmon event IDs**

| ID | Meaning |
|---|---|
| ⭐ **1** | Process creation, with full command line, hashes and parent process |
| **3** | Network connection |
| **7** | Image (DLL) loaded |
| **8** | CreateRemoteThread: code injection |
| **10** | Process access: e.g. LSASS credential dumping |
| **11** | File created |
| **12 / 13** | Registry key created or deleted / value set: persistence |
| **22** | DNS query |

**Linux authentication logs (`auth.log` / journald)**

| Log text | Meaning |
|---|---|
| ⭐ `Invalid user … from <IP>` | Login with a non-existent user |
| ⭐ `Failed password for …` | Wrong password |
| ⭐ `Accepted password for … from <IP>` | Successful password login |
| `Accepted publickey for …` | Successful key-based login |
| ⭐ `session opened` / `session closed` | Start and end of a session |
| `sudo: … COMMAND=…` | Command run with root rights |

---

## 5. SOC Dashboard

I built a **Home SOC Lab Dashboard** with three panels. It turns the telemetry from section 4 into a view an analyst can read at a glance. All panels use the `wazuh-archives*` index pattern; the time range is the last 90 days.

![Home SOC Lab Dashboard with three panels](images/21-dashboard-full.png)

| Panel | Type | Query / filter | Configuration | Question it answers |
|---|---|---|---|---|
| **Failed Windows Logon** | Metric | `data.win.system.eventID: 4625` | Count | How many failed Windows logons? A sudden rise can mean brute force. |
| **Windows Account Changes Over Time** | Line chart | `data.win.system.eventID: ("4720" OR "4722" OR "4723" OR "4724" OR "4725" OR "4726" OR "4732" OR "4733" OR "4738")` | X-axis: date histogram on `timestamp` (per day) · Split series: terms on `data.win.system.eventID` | When were accounts created, enabled, changed, deleted or added to groups? |
| **Linux Failed SSH Authentication Activity** | Data table | `"Failed password"` · filter `agent.name: ubuntu-agent` | Split rows: `agent.name`, `@timestamp`, `data.srcuser`, `data.srcip` | Who tried to log in over SSH, as which user, and from where? |

**Failed Windows Logon (metric).** One number that shows the volume of event 4625.

![Metric panel: count of failed Windows logons](images/22-panel-failed-logon-metric.png)

**Windows Account Changes Over Time (line chart).** Each event ID is a separate line, so a spike in a single type (for example many 4720 account creations) is easy to see. The two data points match the two days on which I ran the account tests.

![Line chart: Windows account-change events per day, split by event ID](images/23-panel-account-changes-line.png)

**Linux Failed SSH Authentication Activity (data table).** The table shows the brute force from section 4 in one view: three failed logins as `fakeuser`, all from `192.168.15.131`, within ten seconds.

![Data table: failed SSH logins on ubuntu with user and source IP](images/24-panel-failed-ssh-table.png)

**Problems met**

| Problem | Cause | Fix |
|---|---|---|
| The account-changes query failed with `6 of 21 shards failed` and `query_shard_exception: [nested] failed to find nested object under path [data.win.system.eventID]`. | DQL read the query as a **nested-field** query. In DQL, curly braces `{ }` mean "search inside nested objects", but `eventID` is a simple field. Only the daily indices that contain this field failed, which is why 6 of 21 shards returned errors. | Grouped the values with normal parentheses: `data.win.system.eventID: ("4720" OR "4722" OR …)`. |
| Event 4726 (account deleted) did not appear in the line chart, although the events existed. | The *Split series* terms aggregation shows only the top *N* event IDs by count (the **Size** setting). Low-count IDs such as 4726 were cut off. | Increased **Size** to 10, so all nine queried IDs can appear. |

![Error: query_shard_exception for a nested query on data.win.system.eventID](images/25-dashboard-query-error.png)

---

## 6. File Integrity Monitoring + Custom Rules

### 6.1 File Integrity Monitoring (FIM)

**Goal:** detect changes to sensitive business files in near real time.

| Agent | Monitored path | Test file | Mode |
|---|---|---|---|
| windows-agent | `C:\CompanyData` | `payroll.txt` | `realtime="yes"` |
| ubuntu-agent | `/opt/company-data` | `payroll` | `realtime="yes"` |

Without `realtime="yes"`, syscheck scans only on its schedule (`<frequency>43200</frequency>` = every 12 hours).

#### Windows agent

A test folder with a payroll file:

![Windows CompanyData folder](images/26-fim-win-companydata.png)

The agent config is `C:\Program Files (x86)\ossec-agent\ossec.conf`. Notepad must run as Administrator to save it.

![Opening ossec.conf](images/27-fim-win-ossec-conf-open.png)

Added inside the `<syscheck>` block:

```xml
<directories realtime="yes">C:\CompanyData</directories>
```

![Windows syscheck config](images/28-fim-win-ossec-conf.png)

Restart the agent (Services → Wazuh → Restart) to load the new config:

![Restart Wazuh agent service](images/29-fim-win-agent-restart.png)

#### Linux agent

Added to `/var/ossec/etc/ossec.conf` inside `<syscheck>`:

```xml
<directories realtime="yes">/opt/company-data</directories>
```

![Linux syscheck config](images/31-fim-linux-ossec-conf.png)

```bash
sudo systemctl restart wazuh-agent.service
```

![Restart Linux agent](images/32-fim-linux-agent-restart.png)

#### Test and result

On both agents: edit the payroll file, save it, then delete it.

![Edit payroll on Linux](images/33-fim-linux-payroll-edit.png)

![Delete payroll on Linux](images/34-fim-linux-delete.png)

| Time (UTC+1) | Agent | syscheck.path | syscheck.event | Rule | Level |
|---|---|---|---|---|---|
| 02:31:56 | windows-agent | `c:\companydata\payroll.txt` | modified | 550 – Integrity checksum changed | 7 |
| 02:33:52 | windows-agent | `c:\companydata\payroll.txt` | deleted | 553 – File deleted | 7 |
| 02:48:42 | ubuntu-agent | `/opt/company-data/payroll` | modified | 550 – Integrity checksum changed | 7 |
| 02:49:28 | ubuntu-agent | `/opt/company-data/payroll` | deleted | 553 – File deleted | 7 |

![FIM events – Windows](images/30-fim-win-events.png)

![FIM events – Linux](images/35-fim-linux-events.png)

**MITRE ATT&CK (Wazuh built-in mapping)**

| Rule | Technique |
|---|---|
| 550 – checksum changed | T1565.001 – Stored Data Manipulation (Impact) |
| 553 – file deleted | T1070.004 – File Deletion (Defense Evasion), T1485 – Data Destruction (Impact) |

---

### 6.2 Custom rule: Windows Guest account enabled

**Why this rule:** The built-in Guest account is disabled by default. If someone enables it, the attacker gets a valid account for access and persistence. Wazuh has a generic rule for this (60109 "User account enabled or created", level 8), but it gives the same level for every account. A dedicated level-12 rule makes this case stand out in triage.

| Item | Value |
|---|---|
| Rule ID | 100200 (custom rules use 100000+) |
| Level | 12 |
| Trigger | Event ID **4722** (account enabled) **and** target user **Guest** |
| Parent | `if_sid 60103` (Windows security account events) |
| MITRE ATT&CK | T1078 – Valid Accounts |
| File | `/var/ossec/etc/rules/local_rules.xml` (Server management → Rules → Custom rules) |

Start state: the Guest account is disabled.

![Guest account disabled](images/36-rule-guest-disabled.png)

![Custom rules – local_rules.xml](images/37-rule-custom-rules-list.png)

#### Attempt 1: the rule did not fire

```xml
<group name="windows,security,account_management,">
  <rule id="100200" level="12">
    <field name="data.win.system.eventID">^4722$</field>
    <field name="data.win.eventdata.targetUserName">^Guest$</field>
    <description>Windows Guest account was enabled.</description>
    ...
  </rule>
</group>
```

![Rule v1 with data. prefix](images/38-rule-v1-data-prefix.png)

Test: uncheck **Account is disabled** → Apply.

![Enable Guest account](images/39-rule-guest-enable.png)

Result: only the built-in alerts 60109 and 60110 appeared. No alert from 100200.

![No custom alert](images/40-rule-v1-no-alert.png)

#### Root cause analysis

1. Opened the alert that did fire and checked `rule.id` → 60110.

   ![Rule 60110 details](images/41-rule-60110-details.png)

2. Searched the rule ID and opened its file `0580-win-security_rules.xml`.

   ![Search rule 60110](images/42-rule-60110-search.png)

3. Compared the built-in rule with mine:

   ![Built-in rule field names](images/43-rule-builtin-field-names.png)

   - Built-in rules use `win.system.eventID`, **without** the `data.` prefix. `data.` exists only in the indexer/dashboard document. The rule engine works on the decoded fields.
   - Built-in rules use `<if_sid>60103</if_sid>`. This links the rule into the Windows security rule chain.

4. Checked the groups of the built-in rules, to keep the alert in the same groups:

   ![Rule 60109 groups](images/44-rule-60109-groups.png)

   ![Rule 60110 groups](images/45-rule-60110-groups.png)

#### Attempt 2: final rule

```xml
<group name="windows,security,account_changed,adduser">

  <rule id="100200" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4722$</field>
    <field name="win.eventdata.targetUserName">^Guest$</field>

    <description>Windows Guest account was enabled.</description>

    <mitre>
      <id>T1078</id>
    </mitre>

    <group>
      windows,
      windows_account_management,
      account_enabled,
      guest_account,
    </group>
  </rule>

</group>
```

![Rule v2 fixed](images/46-rule-v2-fixed.png)

Test again: disable Guest (03:51:06 → rule 60111) and enable it (03:51:12).

**Result:** `Windows Guest account was enabled.` fired at 03:51:12.

![Custom alert fired](images/47-rule-v2-alert-fired.png)

#### Problems met

| Problem | Cause | Fix |
|---|---|---|
| Custom rule 100200 did not fire | Used dashboard field names (`data.win...`). The rule engine uses decoded field names (`win.system.eventID`). No `if_sid`. | Copied the field names and `if_sid 60103` from the built-in rule file `0580-win-security_rules.xml`. |

---

## 7. Active Response

**Goal:** block the source IP automatically after repeated SSH login failures.

| Item | Value |
|---|---|
| Trigger | Custom rule **100101** – 3 SSH authentication failures from the same source IP in 120 seconds |
| Action | `firewall-drop` (iptables DROP for the source IP) |
| Runs on | `ubuntu-agent` (`<location>local</location>`) |
| Attacker | `windows` – 192.168.15.131 |
| Result | 192.168.15.131 blocked on ubuntu at 04:34:21 |

### 7.1 Detection rule for repeated SSH failures

Three failed SSH passwords from the Windows VM to ubuntu:

```powershell
ssh ubuntu@192.168.15.129
```

![Failed SSH logins from Windows](images/48-ar-ssh-fail-before.png)

Without a correlation rule, Wazuh shows only one alert per failed attempt (`sshd: authentication failed`, `unix_chkpwd: Password check failed`, `PAM: User login failed`):

![Alerts before the custom rule](images/49-ar-alerts-before-rule.png)

Custom rule added to `local_rules.xml`:

```xml
<group name="local,syslog,sshd,authentication_failed,">

  <rule id="100101" level="10" frequency="3" timeframe="120">
    <if_matched_sid>5760</if_matched_sid>
    <same_source_ip />

    <description>Multiple SSH login failures observed from the same source IP.</description>

    <mitre>
      <id>T1110</id>
    </mitre>

    <group>authentication_failed,ssh_bruteforce,credential_access,</group>
  </rule>

</group>
```

| Element | Meaning |
|---|---|
| `if_matched_sid 5760` | Counts built-in alerts 5760 (`sshd: authentication failed`) |
| `frequency="3" timeframe="120"` | 3 matches in 120 seconds |
| `same_source_ip` | All 3 matches must come from the same IP |
| T1110 | Brute Force (Credential Access) |

![Rule 100101](images/50-ar-rule-100101.png)

Same test again:

![Failed SSH logins – retest](images/51-ar-ssh-fail-retest.png)

Rule 100101 fired at 04:14:58:

![Rule 100101 fired](images/52-ar-rule-100101-fired.png)

### 7.2 Active response configuration

On the Wazuh server, `/var/ossec/etc/ossec.conf` has a commented example block. It was replaced with an active block:

![Default commented block](images/53-ar-ossec-conf-template.png)

```xml
<active-response>
  <disabled>no</disabled>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100101</rules_id>
</active-response>
```

![Active response block](images/54-ar-ossec-conf-block.png)

```bash
sudo systemctl restart wazuh-manager.service
sudo /var/ossec/bin/agent_control -L
```

![Restart manager](images/55-ar-manager-restart.png)

![Available active responses](images/56-ar-agent-control.png)

### 7.3 Test

A continuous ping from Windows to ubuntu runs in one window. SSH login failures are generated in a second window.

![Ping stops after the block](images/57-ar-ping-blocked.png)

| Time (UTC+1) | Event |
|---|---|
| 04:34:11 – 04:34:19 | 3 failed SSH passwords from 192.168.15.131 |
| 04:34:19 | Rule 100101 – Multiple SSH login failures observed from the same source IP |
| 04:34:21 | Host Blocked by firewall-drop Active Response |
| after 04:34:21 | Ping from Windows: `Request timed out` |

![Host blocked alert](images/58-ar-host-blocked-alert.png)

### 7.4 Verification and unblock

On ubuntu, `iptables` shows a DROP rule for 192.168.15.131 in the INPUT and FORWARD chains. This config has no `<timeout>`, so the block stays until it is removed by hand:

```bash
sudo iptables -L -n --line-numbers
sudo iptables -D INPUT 1
sudo iptables -D FORWARD 1
```

![iptables DROP rules removed](images/59-ar-iptables-unblock.png)

---

## 8. Investigation

**Scenario:** SSH brute force against `ubuntu`, followed by a successful login and data staging (activity from section 4.2).

| Question | Finding |
|---|---|
| What happened? | 3 failed SSH logins (`fakeuser`), then a successful password login as `ubuntu` from the same IP. In the session: `ip a`, `whoami`, `cat /etc/passwd`, and `/etc/passwd` copied to `/tmp/loot.txt`. |
| Which host / user? | Target: `ubuntu-agent` (192.168.15.129), user `ubuntu`. Source: `windows` (192.168.15.131). |
| When? (UTC) | 20:09:01 failed logins → 20:09:18 login (session 5, sshd PID 3328) → 20:10:08 first command → 21:26:03 logout. |
| How was it detected? | sshd/PAM alerts (failed logins, *authentication success*) and Sysmon for Linux process events with `TerminalSessionId 5`. |
| Verdict | True positive (simulated attack). |
| Recommended next steps | Reset the `ubuntu` password, block 192.168.15.131 (rule 100101 + `firewall-drop`, section 7), delete `/tmp/loot.txt`, check the other hosts for logins from .131. |

---

## 9. Lessons Learned

- Rules use the decoded field names (`win.system.eventID`), not the dashboard names (`data.win...`). The built-in rule files show the correct names.
- Every `ossec.conf` change needs a service restart (manager or agent).
- Normalize time zones first: raw Linux logs are UTC, the dashboard is UTC+1.
- In visualizations, check the terms **Size** before you decide that an event is missing.
- `firewall-drop` without `<timeout>` blocks the IP until it is removed by hand.

---

> ⚠️ All activity was performed in an isolated lab environment owned by the author.
