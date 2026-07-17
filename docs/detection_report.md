# SIEM Threat Detection Use Cases Report

This report outlines the threat detection use cases configured within the SIEM environment. Each use case is mapped to the MITRE ATT&CK framework and includes the corresponding KQL search filter, logic thresholds, and recommended response procedures.

---

## 1. SSH Brute-Force Login Attempt
* **MITRE ATT&CK Technique**: [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
* **Severity**: **Medium** (Escalates to **High** if a successful login follows failures from the same IP)
* **KQL Query**:
  ```kql
  event.category: "authentication" AND event.action: "ssh_login" AND event.outcome: "failure"
  ```
* **Detection Logic**: Trigger alert when the number of events matching this query from a single `source.ip` exceeds 5 within a 1-minute window.
* **Analyst Action / Remediation**:
  1. Inspect the `source.ip`. Determine if it belongs to an authorized internal subnet or a public IP address.
  2. Perform a reverse DNS lookup and check threat intelligence sources (e.g., AbuseIPDB, VirusTotal).
  3. If external, block the IP at the perimeter firewall.
  4. Verify if any subsequent login event (`event.outcome: "success"`) occurred from the same `source.ip` to the target user. If so, declare a breach and initiate credential rotation.

---

## 2. Windows RDP Brute-Force Attack
* **MITRE ATT&CK Technique**: [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
* **Severity**: **High**
* **KQL Query**:
  ```kql
  event.category: "authentication" AND event.action: "win_login" AND event.outcome: "failure" AND event.code: 4625
  ```
* **Detection Logic**: Trigger when 10+ failed logon events (Event ID 4625) are recorded on a single host from the same source workstation/IP in 5 minutes.
* **Analyst Action / Remediation**:
  1. Review the `user.name` targeted. Brute-force attacks frequently target default accounts like `Administrator` or `guest`.
  2. Block the offending network IP in the local host Windows Firewall or core subnet gateway.
  3. Ensure Account Lockout Policies are active on the host machine to block brute-force attempts.

---

## 3. Linux Privilege Escalation (Sudo Misuse)
* **MITRE ATT&CK Technique**: [T1548.003 - Abuse Elevation Control Mechanism: Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/)
* **Severity**: **High**
* **KQL Query**:
  ```kql
  event.category: "iam" AND event.action: "privilege_escalation" AND event.outcome: "failure"
  ```
  *(Logstash filters parse `user NOT in sudoers` or failed sudo validations into this taxonomy).*
* **Detection Logic**: Triggers on any singular instance of a failed sudo execution or attempted access by a non-privileged user.
* **Analyst Action / Remediation**:
  1. Check the `process.command_line` to see what command the user was attempting to run as root.
  2. Cross-reference the timestamp with authorized maintenance windows or tickets.
  3. Interview the employee (`user.name`) to verify authorization. If suspicious, temporarily disable the user account.

---

## 4. Credential Dumping (Mimikatz Process Injection)
* **MITRE ATT&CK Technique**: [T1003.001 - OS Credential Dumping: LSA Secrets](https://attack.mitre.org/techniques/T1003/001/)
* **Severity**: **Critical**
* **KQL Query**:
  ```kql
  event.category: "process" AND event.action: "process_creation" AND (process.name: "mimikatz.exe" OR process.command_line: *mimikatz* OR process.command_line: *sekurlsa*)
  ```
* **Detection Logic**: Triggers instantly (0-second latency threshold) upon detection of the keyword or process execution.
* **Analyst Action / Remediation**:
  1. **Immediate Quarantine**: Isolate the target Windows host from the network using EDR tools.
  2. Terminate the offending process ID.
  3. Audit the LSASS process memory space for unauthorized reads or dumps.
  4. Perform global credential reset for all accounts logged into that host within the past 48 hours.

---

## 5. Reconnaissance & Port Scanning (Nmap Activity)
* **MITRE ATT&CK Technique**: [T1595.001 - Active Scanning: IP Addresses](https://attack.mitre.org/techniques/T1595/001/)
* **Severity**: **Low** to **Medium**
* **KQL Query**:
  ```kql
  event.category: "network" AND event.action: "network_flow" AND network.transport: "tcp" AND connection.status: "rejected"
  ```
* **Detection Logic**: Trigger when a single source IP connects to more than 50 distinct destination ports on a single host in under 10 seconds.
* **Analyst Action / Remediation**:
  1. Verify if the source IP is an authorized vulnerability scanner (e.g., Nessus, Qualys, OpenVAS).
  2. If the scan is unauthorized, restrict the source IP on host-level TCP Wrappers or boundary firewalls.
  3. Verify if any ports scanned were open and successfully negotiated a connection.

---

## 6. Anomalous Data Exfiltration
* **MITRE ATT&CK Technique**: [T1048 - Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048/)
* **Severity**: **High**
* **KQL Query**:
  ```kql
  event.category: "network" AND network.bytes_written > 500000000
  ```
  *(Filter looks for network flows where outbound data transferred exceeds 500MB).*
* **Detection Logic**: Trigger on single connections transferring >500MB outbound, or aggregated transfers >2GB from a single host in 1 hour to an external address.
* **Analyst Action / Remediation**:
  1. Audit the source host and identify the parent process establishing the socket (`process.name`).
  2. Determine the destination IP and check its ownership (e.g. AWS, Mega.nz, Dropbox, external staging servers).
  3. Stop the network process or terminate the connection immediately.
  4. Review compliance policies and verify if data contains Sensitive or Personally Identifiable Information (PII).
