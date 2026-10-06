# Hidden for 51 Weeks: Investigating a NetSupport RAT Compromise

![Category](https://img.shields.io/badge/Category-Incident%20Response%20%2F%20DFIR-blue)
![Type](https://img.shields.io/badge/Type-Real--World%20Case%20Study-red)
![Platform](https://img.shields.io/badge/Platform-Windows%2011-0078D6)
![Tools](https://img.shields.io/badge/Tools-PowerShell%20%7C%20Defender%20%7C%20VirusTotal-5391FE)
![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange)

**Detection, investigation, root cause analysis and recovery of a real NetSupport Remote Access Trojan infection.**

> **Note:** This is a real incident, not a lab. Usernames, hostnames and personal details have been replaced with placeholders such as `<user>` and `<host>`, and screenshots have been redacted accordingly. All network indicators are defanged.

| Field | Detail |
|---|---|
| Prepared by | Osita Kingsley Odo, Cybersecurity Specialist |
| Report date | 5 October 2026 |
| Affected host | `<host>` (Windows 11) |
| Malware family | NetSupport Manager abused as a Remote Access Trojan (NetSupport RAT) |
| Severity | High |
| Status | Contained; accounts secured; Windows rebuild pending |
| Distribution | TLP:CLEAR for indicators of compromise |

## 1. Executive summary

On 5 October 2026 a recurring Windows error ("service.exe - System
Error: PCICL32.dll was not found") led to the discovery of a NetSupport
Remote Access Trojan on the author's personal laptop. NetSupport Manager
is legitimate commercial remote-control software, but criminal groups
widely repackage it to gain hidden, persistent access to victims'
computers.

The investigation established that the RAT was installed on 2 September
2025 at 16:16 local time by a PowerShell loader that created a hidden
folder (%APPDATA%\Svservices), downloaded an installer from
devenable[.]dev and ran it silently. The RAT was configured to connect to
two attacker-controlled gateways, sonosarcx[.]com and sonosarcl[.]net, on
port 2080.

Microsoft Defender did not detect the infection until 26 August 2026,
when it quarantined one component (PCICL32.dll). Because the rest of the
toolkit remained, the launcher kept starting and failing, which produced
the error that triggered this investigation.

**Key conclusions:**

- **Exposure window:** about 51 weeks (2 September 2025 to 26 August
  2026), during which an attacker could have viewed the screen,
  controlled the computer and transferred files.

- **Current state:** the RAT is broken and no recent connections to the
  command servers were found, but the host cannot be considered
  trustworthy.

- **Initial access:** the second-stage loader was identified; the first
  step that ran it was not confirmed. The evidence is most consistent
  with a fake browser prompt that tricks the user into running a command
  (the "ClickFix" technique).

- **Several false leads were ruled out:** the TradingView and easyroam
  installers downloaded that day are genuine and signed, and the
  suspicious-looking servicehost.exe process is McAfee WebAdvisor.

- **Actions taken:** the malware folder was deleted, precautionary steps were taken on financial accounts, personal files were backed up, and all
  passwords were changed from a clean device with multi-factor
  authentication verified. No organisational data was affected.

## 2. Scope, environment and method

| **Item**           | **Detail**                                                                                                                                                                          |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Host               | Personal laptop, Windows 11, hostname \<host\>                                                                                                          |
| User context       | Local user `<user>`; machine used for study, professional work and a cybersecurity home lab (Splunk, VS Code)                                                                        |
| Location           | Germany; times in this report are local time (CEST, UTC+2) unless marked UTC                                                                                                  |
| Investigation date | 5 October 2026                                                                                                                                                                      |
| Tools              | Task Manager, File Explorer, Windows PowerShell (standard and elevated), Microsoft Defender operational log, Authenticode signature checks, NTFS alternate data streams, VirusTotal |

The investigation was carried out live on the affected host. Evidence
was captured by photographing the screen. File system timestamps were
used to build the timeline; dropped files can carry timestamps from the
attacker's build environment, so folder creation times were preferred
where available.

## 3. Detection

The incident was detected through a Windows error dialog that kept
appearing on screen. It stated that service.exe could not run because
PCICL32.dll was missing.

<img width="875" height="358" alt="image" src="https://github.com/user-attachments/assets/9f4279de-4e36-457d-9c3d-23161580d935" />


*Figure 1: Error dialog that triggered the investigation*

PCICL32.dll is the core client library of NetSupport Manager. An
unfamiliar program called service.exe failing to load it strongly
suggested a NetSupport RAT whose main library had been removed by
antivirus, while its launcher and persistence remained in place.

## 4. Investigation and findings

### 4.1 Running processes

The Task Manager Details view showed two processes of interest:

| **Process**     | **PID** | **User** | **Notes**                                                                                                      |
|-----------------|---------|----------|----------------------------------------------------------------------------------------------------------------|
| service.exe     | 22572   | \<user\>   | 32-bit process, consistent with the NetSupport client (client32.exe) renamed. Running from the staging folder. |
| servicehost.exe | 6076    | SYSTEM   | Not a standard Windows name, so initially treated as suspicious. Later resolved as legitimate (section 4.7).   |

<img width="940" height="632" alt="image" src="https://github.com/user-attachments/assets/514c59ea-56b1-491d-a7e0-c9bec7e629c0" />

*Figure 2: Task Manager Details view showing service.exe (PID 22572) and servicehost.exe (PID
6076)*

<img width="946" height="489" alt="image" src="https://github.com/user-attachments/assets/46a65a05-7e8e-412b-a22a-be1d00db6e8f" />

*Figure 3: Non-elevated query for PID 6076 returning no path or command
line*

#### Commands used at this stage

<img width="921" height="458" alt="image" src="https://github.com/user-attachments/assets/0b0b6577-7f6c-4425-91e9-38e3d9ea91eb" />


### 4.2 Staging folder

The launcher was located in `C:\Users\<user>\AppData\Roaming\Svservices`.
The folder name imitates "services" with a misspelling, a common
disguise. Its contents form a complete NetSupport client kit:

<img width="762" height="541" alt="image" src="https://github.com/user-attachments/assets/1b6f373d-3ca1-4c56-813e-a586f2ccd40e" />

<img width="936" height="719" alt="image" src="https://github.com/user-attachments/assets/57bf6367-98ad-4b7f-b8aa-fff1409915ce" />
*Figure 4: Contents of %APPDATA%\Svservices in File Explorer*


<img width="932" height="367" alt="image" src="https://github.com/user-attachments/assets/109fdfa5-f9d6-4680-bbdd-dc67ecc2b46a" />
*Figure 5: Earliest Defender events and the creation time of the
Svservices folder (showing 2 September 2025, 16:16:45)*

#### Commands used at this stage

<img width="770" height="271" alt="image" src="https://github.com/user-attachments/assets/bd4e69a7-afb4-4dd3-b499-85e233805a2c" />

### 4.3 Configuration analysis (client32.ini)

The configuration file was read as plain text without running anything.
It shows a client set up for covert, attacker-controlled use:

<img width="786" height="601" alt="image" src="https://github.com/user-attachments/assets/d9e302e4-3564-4df3-bedb-a056735f98f4" />               

The domain names loosely imitate the Sonos brand. A web search at the
time of the investigation found no public reporting on either domain.

<img width="938" height="513" alt="image" src="https://github.com/user-attachments/assets/f818a575-c0f9-47d3-871b-66b912ed12f1" />
*Figure 6: client32.ini, \[Client\] section: silent operation, hidden
tray icon and disabled user controls*

<img width="938" height="536" alt="image" src="https://github.com/user-attachments/assets/b8088721-073a-461e-a9bb-f0630cfc232c" />
*Figure 7: client32.ini, \[HTTP\] section: gateways sonosarcx[.]com and
sonosarcl[.]net on port 2080*

#### Commands used at this stage
<img width="780" height="166" alt="image" src="https://github.com/user-attachments/assets/7c994129-9e23-41f6-9caf-8d7442cf7591" />

### 4.4 Network activity

The DNS cache contained no entries for the "sonosarc" domains, and
`Get-NetTCPConnection -RemotePort 2080` returned no connections.
This is consistent with the RAT having been unable to run since its main
library was removed on 26 August 2026. No historical network logs were
available to show earlier connections.

#### Commands used at this stage

<img width="772" height="211" alt="image" src="https://github.com/user-attachments/assets/20c55100-4f4f-4bc2-a21f-83c3313d03cf" />


### 4.5 Microsoft Defender detection history

<img width="775" height="187" alt="image" src="https://github.com/user-attachments/assets/dadd89ef-ecf9-4b90-9009-268ab9234df4" />

These were the only Defender events matching the investigation keywords.
Defender classified the file as a "Tool" rather than a trojan, because
NetSupport is commercial software. It removed only the one detected
library and left the launcher, configuration, installer and persistence
in place. This explains both the late detection and the recurring error.

<img width="938" height="495" alt="image" src="https://github.com/user-attachments/assets/f57a8056-3fea-414a-8345-d839527e68be" />
*Figure 8: DNS and port 2080 checks (no results), and the Defender
quarantine event at 11:20:44*

<img width="938" height="495" alt="image" src="https://github.com/user-attachments/assets/f57c45ac-e47e-4052-b590-08f230da6017" />
*Figure 9: Defender detection event at 11:19:40 for PCICL32.DLL loaded
by service.exe*

#### Commands used at this stage

<img width="836" height="361" alt="image" src="https://github.com/user-attachments/assets/6e1ab9bb-2475-4aa7-ae89-f4211286ba3e" />

### 4.6 File system timeline for 2 September 2025

The staging folder was created on **2 September 2025 at 16:16:45**. A
recursive search of the user profile, including hidden folders, produced
the following sequence:

<img width="672" height="660" alt="image" src="https://github.com/user-attachments/assets/be819071-319f-41c3-b18d-585c06a2eded" />
                        
No file was created in the user profile between 15:31 and 16:16.
Whatever started the infection therefore left no file of its own behind,
which points to a command or script run directly rather than a
downloaded file that was opened.

<img width="938" height="289" alt="image" src="https://github.com/user-attachments/assets/b4e33895-0791-4e20-9761-0fc663b7cbf3" />
*Figure 10: First file search for 2 September 2025 without -Force:
hidden folders skipped*

<img width="931" height="652" alt="image" src="https://github.com/user-attachments/assets/fda0696b-8704-45a6-abb7-e3c6abcd554f" />
*Figure 11: Elevated file search with -Force, showing hidden AppData
artefacts from 2 September 2025*

<img width="938" height="495" alt="image" src="https://github.com/user-attachments/assets/50c6fb1c-3519-40b3-b61a-f11eb849a2e0" />
*Figure 12: Timeline export (sep2_timeline.csv): Svservices, fe0.msi and
NetSupport created 16:16:45 to 16:16:52, followed by the genuine
TradingView install*

#### Commands used at this stage

<img width="765" height="562" alt="image" src="https://github.com/user-attachments/assets/2bbb457e-78c5-4064-9dd6-2e68188dc562" />



### 4.7 False leads ruled out

Several items were initially treated as suspicious and then checked.
Recording these is important because two early hypotheses turned out to
be wrong.

<img width="773" height="397" alt="image" src="https://github.com/user-attachments/assets/32fe2c8c-d1f5-4abf-b9ab-e87070cf0206" />


<img width="938" height="805" alt="image" src="https://github.com/user-attachments/assets/f15a14a1-6f8c-48db-adfe-2c9dc98294e7" />
*Figure 13: Valid Authenticode signatures for the TradingView and
easyroam installers*

#### Commands used at this stage

<img width="720" height="658" alt="image" src="https://github.com/user-attachments/assets/9bbb9000-45f7-4d7b-8a18-b48f979d2341" />


### 4.8 Initial access analysis

<img width="632" height="267" alt="image" src="https://github.com/user-attachments/assets/fe71e59b-065b-4d53-967c-d4e1f31f85dc" />

Commands pasted into the Win+R box run PowerShell non-interactively and
do not appear in PowerShell history. Combined with the absence of any
dropped file before 16:16, this makes a fake verification prompt
("ClickFix") the most likely first step, but it could not be proven.

#### Commands used at this stage

<img width="702" height="417" alt="image" src="https://github.com/user-attachments/assets/63f44ccd-d180-4e55-a252-c0e585a49378" />

### 4.9 Threat intelligence (VirusTotal)

**Installer (fe0.msi).** The SHA-256 hash was looked up on VirusTotal:

- 11 of 62 vendors flag it; popular label hacktool.netsup, family
  netsup. ESET, Kaspersky and Dr.Web name NetSupport specifically.

- Behaviour tags detect-debug-environment and checks-usb-bus show
  sandbox evasion, which a genuine NetSupport installer has no reason to
  do.

- Built 8 August 2025 05:34 UTC (07:34 local), matching the client32.ini
  modification time of 07:27 that morning. First submitted 12 August
  2025, last submitted 26 January 2026: an active campaign over several
  months.

- Also seen as 5d60a0aa.msi and 19be0a8c.msi, short random names typical
  of automated download-and-run delivery.

- Dropped files include Binary.aicustact.dll, showing the package was
  built with Advanced Installer.

- Execution parents: crap.zip (27/69) and a PowerShell script named
  malicous.msi.

- Sandbox network traffic contained only Microsoft, Akamai and Let's
  Encrypt endpoints. The sonosarc gateways do not appear, so they are
  new intelligence.

<img width="938" height="344" alt="image" src="https://github.com/user-attachments/assets/260bafbb-7ca5-472b-b3fd-2ec1e8ad6fce" />
*Figure 14: No MsiInstaller events for 2 September 2025, and SHA-256
hashes of fe0.msi and service.exe*

<img width="938" height="495" alt="image" src="https://github.com/user-attachments/assets/c8541132-2797-42ac-af74-ee48f8b46bd7" />
*Figure 15: VirusTotal detection page for fe0.msi (11/62,
hacktool.netsup)*

<img width="938" height="520" alt="image" src="https://github.com/user-attachments/assets/63433a7d-74fc-4427-a4f3-ad79117e2187" />
*Figure 16: VirusTotal Details tab for fe0.msi showing file hashes and
type*

<img width="938" height="495" alt="image" src="https://github.com/user-attachments/assets/43fcc401-f714-4574-b4d9-b0e59950c547" />
*Figure 17: VirusTotal Relations: contacted IP addresses and execution
parents (crap.zip and the PowerShell loader)*

<img width="938" height="495" alt="image" src="https://github.com/user-attachments/assets/553cf5e4-21fa-466c-bf1b-25a97530fb50" />
*Figure 18: VirusTotal Relations: bundled and dropped files, including
Binary.aicustact.dll*

<img width="938" height="495" alt="image" src="https://github.com/user-attachments/assets/e0753e6a-4ddf-414e-b544-922b874a77be" />
*Figure 19: VirusTotal Relations: contacted domains (benign Microsoft,
Akamai and Let's Encrypt traffic)*

**PowerShell loader (malicous.msi).** Despite its name, this 538-byte
file is a PowerShell script. No vendor flags it (0/61), but VirusTotal
Code Insights and the NICS Lab crowdsourced analysis describe exactly
what happened on the affected host:

1.  Creates %APPDATA%\Svservices if it does not exist.

2.  Downloads `https://devenable[.]dev/fe0.msi` into that folder.

3.  Runs msiexec.exe to install fe0.msi silently, with restarts
    suppressed, and waits for it to finish.

4.  Restores the previous working directory.

<img width="938" height="534" alt="image" src="https://github.com/user-attachments/assets/82da57f1-68f9-487f-b8db-e7c03600d238" />
*Figure 20: VirusTotal Code Insights for the PowerShell loader, naming
devenable[.]dev/fe0.msi*

Report links: [fe0.msi on
VirusTotal](https://www.virustotal.com/gui/file/528373aa38e1139ce6b5325ef25cc756de2162c9ca58f7fbec2afaf8e3ceab1c);
[PowerShell loader on
VirusTotal](https://www.virustotal.com/gui/file/ea4de238a6ce0943c9eebf367ceb76d777a8c68c45c61da067c363923cec1813).

#### Commands used at this stage

<img width="882" height="615" alt="image" src="https://github.com/user-attachments/assets/1d41f7b0-797a-476e-aa05-2c1348193f53" />


## 5. Attack chain

| **Stage**               | **What happened**                                                                           | **Evidence**                                                                          | **Confidence**                                 |
|-------------------------|---------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------|------------------------------------------------|
| 0\. Initial access      | User tricked into running a command, most likely through a fake browser verification prompt | No dropped file before 16:16; nothing in PowerShell history; delivery is script-based | Low to medium                                  |
| 1\. Loader              | PowerShell creates Svservices and downloads fe0.msi from devenable[.]dev                      | VirusTotal code analysis matches folder name, file name and timing                    | High                                           |
| 2\. Installation        | msiexec installs NetSupport silently                                                        | NetSupport folders created at 16:16:52                                                | High                                           |
| 3\. Command and control | Hidden client connects to sonosarcx[.]com / sonosarcl[.]net on port 2080                        | client32.ini configuration                                                            | High (configuration); connections not observed |
| 4\. Detection           | Defender quarantines PCICL32.dll; RAT stops working                                         | Defender log, 26/08/2026                                                              | High                                           |

## 6. MITRE ATT&CK mapping

| **Tactic**          | **Technique**                                                  | **Observation**                          |
|---------------------|----------------------------------------------------------------|------------------------------------------|
| Execution           | T1204.004 User Execution: Malicious Copy and Paste (suspected) | Most likely first step                   |
| Execution           | T1059.001 Command and Scripting Interpreter: PowerShell        | Loader script                            |
| Command and control | T1105 Ingress Tool Transfer                                    | Download of fe0.msi from devenable[.]dev   |
| Defence evasion     | T1218.007 System Binary Proxy Execution: Msiexec               | Silent MSI installation                  |
| Defence evasion     | T1036.005 Masquerading: Match Legitimate Name or Location      | Svservices folder, service.exe           |
| Defence evasion     | T1497.001 Virtualisation/Sandbox Evasion: System Checks        | detect-debug-environment, checks-usb-bus |
| Command and control | T1219 Remote Access Software                                   | NetSupport Manager client                |
| Command and control | T1071.001 Application Layer Protocol: Web Protocols            | HTTP gateway on port 2080                |

**Persistence:** the launcher restarted after reboots, so a persistence
mechanism exists (most likely a Run key or Startup entry, T1547.001).
The exact entry was not confirmed during this investigation.

## 7. Impact assessment

- **Exposure window:** 2 September 2025 16:16 to 26 August 2026 11:20,
  about 51 weeks.

- **Attacker capability during that window:** live screen viewing,
  remote keyboard and mouse control, file transfer and remote command
  execution, all hidden from the user.

- **Data at risk:** every password typed, every session used, every
  password saved in the browser and every file opened on the laptop
  during the window. The owner confirmed that no organisational or
  client data was affected.

- **Evidence of actual misuse:** none collected. No network logs exist
  for the period, so misuse can neither be confirmed nor ruled out. The
  working assumption is that credentials and data were exposed.

- **Current risk:** reduced, because the RAT cannot run without
  PCICL32.dll. The host remains untrusted until rebuilt.

## 8. Indicators of compromise

Network indicators are defanged. Replace \[.\] with . before using them
in tools.

| **Type**       | **Indicator**                                                    | **Context**                             |
|----------------|------------------------------------------------------------------|-----------------------------------------|
| URL            | hxxps://devenable\[.\]dev/fe0.msi                                | Stage 2 download                        |
| Domain:port    | sonosarcx\[.\]com:2080                                           | Primary NetSupport gateway              |
| Domain:port    | sonosarcl\[.\]net:2080                                           | Secondary NetSupport gateway            |
| SHA-256        | ea4de238a6ce0943c9eebf367ceb76d777a8c68c45c61da067c363923cec1813 | PowerShell loader (538 bytes)           |
| SHA-256        | 528373aa38e1139ce6b5325ef25cc756de2162c9ca58f7fbec2afaf8e3ceab1c | fe0.msi (3,954,688 bytes)               |
| SHA-256        | ee60df2b2e463d06d7515900e6e391ea04fa4386f6f9466bdfaf935f7ebb14f3 | service.exe (renamed NetSupport client) |
| SHA-1          | bb9567959269dcd7aced207442cf71b1875115a1                         | fe0.msi                                 |
| MD5            | 4cfc447991904a5bcf13c1d208e38a85                                 | fe0.msi                                 |
| File names     | fe0.msi, 5d60a0aa.msi, 19be0a8c.msi                              | Installer aliases                       |
| Path           | %APPDATA%\Svservices\\                                           | Staging folder                          |
| Path           | %LOCALAPPDATA%\NetSupport\NetSupport Manager                     | Installer artefact                      |
| Detection name | HackTool:Win32/RemoteAdmin!MTB                                   | Microsoft Defender                      |

## 9. Containment, eradication and recovery

Status as at 5 October 2026.

| **\#** | **Action**                                                                                                                                                  | **Status**                                                  |
|--------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------|
| 1      | Investigate and collect evidence (this report)                                                                                                              | Completed                                                   |
| 2      | Record hashes of the malicious files                                                                                                                        | Completed for fe0.msi and the PowerShell loader (section 8) |
| 3      | Delete %APPDATA%\Svservices                                                                                                                                 | Completed                                                   |
| 4      | Remove the remaining startup entry for service.exe                                                                                                          | Covered by the Windows rebuild (action 10)                  |
| 5      | Take precautionary steps on financial accounts | Completed                                                   |
| 6      | Change all passwords from a clean device (mobile phone), including the Google account that holds Google Password Manager                                    | Completed                                                   |
| 7      | Verify multi-factor authentication on all accounts (Google Authenticator, email confirmation prompts, login notifications) and review signed-in device logs | Completed                                                   |
| 8      | Notify organisations whose data was handled on the laptop                                                                                                   | Not required: no organisational data affected               |
| 9      | Back up personal files (documents only, no executables or scripts)                                                                                          | Completed; scan before restoring                            |
| 10     | Reinstall Windows from official Microsoft media and restore scanned personal files                                                                          | Pending                                                     |
| 11     | Do not sign into Chrome or the Google account on the laptop until it is rebuilt                                                                             | In effect                                                   |
| 12     | Submit the indicators in section 8 to ThreatFox and URLhaus (abuse.ch)                                                                                      | Pending                                                     |

### 9.1 Containment and recovery measures taken

The table below records each measure completed and why it was effective
in limiting the impact of the incident.

| **Measure**                                               | **Why it was effective**                                                                                                                    |
|-----------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| Recorded hashes before removal                            | Preserved the key evidence and indicators for threat intelligence and reporting before the malware was deleted.                             |
| Deleted the malware folder (%APPDATA%\Svservices)         | Removed the RAT launcher, configuration and installer, ending the recurring error and preventing any attempt to repair or relaunch the RAT. |
| Took precautionary steps on financial accounts | Reduced the most immediate financial risk, since account details may have been visible during the exposure window. |
| Changed all passwords from a clean device (mobile phone)  | Ensured the new passwords were never typed on, or visible to, the compromised laptop.                                                       |
| Secured the Google account first                          | Protected every password stored in Google Password Manager, since the Google account controls access to all of them.                        |
| Verified multi-factor authentication on all accounts      | Google Authenticator, email confirmation prompts and login notifications mean that a stolen password alone can no longer be used.           |
| Reviewed signed-in device logs                            | Confirmed that no unknown devices or sessions remained with access to the accounts.                                                         |
| Stopped using Chrome and the Google account on the laptop | Prevents new credentials or session cookies being exposed to a host that is still untrusted.                                                |
| Backed up personal files                                  | Protects personal data ahead of the Windows rebuild, limited to documents so that no malicious executables are carried over.                |
| Confirmed no organisational data was affected             | Established that no third-party notification duty applies and narrowed the impact to personal accounts.                                     |

## 10. Limitations

- The first step of the attack (what ran the PowerShell loader) was not
  confirmed. Browser history older than 90 days and Windows Installer
  events from September 2025 were no longer available.

- The exact persistence entry for service.exe was not recorded.

- No network logs exist for the exposure window, so command and control
  activity is inferred from configuration, not observed.

- Evidence was captured as screenshots and photographs rather than as
  forensic images.

## 11. Lessons learned

- **Antivirus labels can understate risk.** Defender filed a full RAT
  under "Tool" and removed one file. Any detection of
  remote-administration software should prompt a full check of the
  surrounding folder and persistence.

- **Test hypotheses before acting on them.** Two early suspects, the
  TradingView installer and servicehost.exe, were legitimate. Signature
  and path checks prevented a wrong root cause from entering the record.

- **Never paste commands from a web page into Win+R or PowerShell.**
  Legitimate sites do not ask users to do this to "verify" themselves.

- **Avoid running remote scripts with administrator rights.** One-line
  commands of the form "irm \<url\> \| iex" give whoever controls that
  URL full control of the machine.

- **Keep logs that outlast the threat.** Forwarding Sysmon, PowerShell
  and DNS logs to the existing Splunk instance would have shown the
  delivery command and any command and control traffic.

## 12. Cybersecurity practice demonstrated

This investigation was a hands-on exercise across several core areas of
cybersecurity. The table below maps what I did to each discipline and
points to where the evidence sits in this report.

| **Discipline**                             | **What I practised**                                                                                                                                                                                         | **Report section** |
|--------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------|
| Incident response                          | Worked through the incident response lifecycle: detection, scoping, analysis, containment planning, eradication and recovery planning, and lessons learned.                                                  | 3, 4, 9, 11        |
| Digital forensics (live response)          | Collected evidence on a running system and reconstructed events from Windows artefacts: NTFS creation times, Recent links, the Mark of the Web (Zone.Identifier), RunMRU, PowerShell history and event logs. | 4.2, 4.6, 4.8      |
| Timeline analysis                          | Built a minute-by-minute timeline of the infection day and correlated local file times with VirusTotal build and submission dates in UTC.                                                                    | 4.6, 4.9           |
| Malware analysis (static)                  | Identified the malware family from file names, a missing DLL and a cracked licence file, and analysed the RAT configuration as text without executing anything.                                              | 4.2, 4.3           |
| Endpoint security and Windows internals    | Assessed processes by user context, architecture and parent process; understood how privileges limit what a standard session can see; reviewed how Defender classifies and remediates threats.               | 4.1, 4.5, 4.7      |
| Threat hunting and hypothesis testing      | Formed hypotheses (TradingView installer, servicehost.exe, ClickFix delivery), tested each against evidence, and discarded the ones the evidence did not support.                                            | 4.7, 4.8           |
| Code signing and supply chain verification | Validated Authenticode signatures, certificate issuers and thumbprints, and download origins to confirm software was genuine.                                                                                | 4.7                |
| Threat intelligence (OSINT)                | Used hash lookups and pivoted through VirusTotal relations (bundled files, execution parents, contacted infrastructure) to find the delivery script and URL.                                                 | 4.9                |
| Indicator management                       | Extracted, verified and defanged indicators of compromise in a format ready for sharing with ThreatFox and URLhaus.                                                                                          | 8                  |
| Threat frameworks                          | Mapped attacker behaviour to MITRE ATT&CK techniques with stated confidence levels.                                                                                                                          | 5, 6               |
| Scripting and troubleshooting              | Wrote and debugged PowerShell queries, and diagnosed failures caused by missing elevation, hidden folders, OneDrive folder redirection and lost syntax.                                                      | 4.6, Appendix A    |
| Risk and impact assessment                 | Estimated the exposure window, attacker capability and data at risk, and prioritised response actions by risk.                                                                                               | 7, 9               |
| Evidence handling                          | Preserved evidence before deletion (hashes, offline copy) and recorded the limits of photo-based capture.                                                                                                    | 9, 10              |
| Security reporting                         | Documented findings, reasoning, confidence and limitations in a structured report for technical and non-technical readers.                                                                                   | Whole report       |

### 12.1 Alignment with the NIST incident response lifecycle

| **NIST SP 800-61 phase**              | **Activities in this incident**                                                                                                                  |
|---------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Preparation                           | Existing tooling on the host (PowerShell, Defender, Splunk) and access to OSINT services. Gaps identified in log retention.                      |
| Detection and analysis                | Error dialog triage, process and file review, configuration analysis, Defender log review, timeline reconstruction, threat intelligence lookups. |
| Containment, eradication and recovery | Planned domain blocking, removal of the RAT and its persistence, credential rotation from a clean device, and a full Windows rebuild.            |
| Post-incident activity                | Lessons learned, indicator sharing with the community, and this report.                                                                          |

### 12.2 Skills to develop next

The investigation also showed where further practice would add value:

- **Forensic acquisition:** capturing disk and memory images (for
  example with FTK Imager or KAPE) instead of photographs, to preserve
  evidence in a defensible form.

- **Logging and detection engineering:** deploying Sysmon and PowerShell
  script block logging, forwarding them to Splunk, and writing
  detections for silent msiexec installs from AppData.

- **Dynamic malware analysis:** detonating samples in an isolated
  sandbox to observe command and control behaviour directly.

- **Persistence hunting:** systematic review of autostart locations with
  tools such as Autoruns.

- **Memory forensics:** using Volatility to examine running malware and
  recover artefacts that never touch the disk.

## Appendix A. Command log in order of execution

All commands were run in Windows PowerShell on the affected host. Steps
marked "elevated" were run with Run as administrator.

| **Step** | **Stage**               | **Command (summary)**                                               | **Outcome**                                               |
|----------|-------------------------|---------------------------------------------------------------------|-----------------------------------------------------------|
| 1        | Process review          | Task Manager \> Details                                             | service.exe and servicehost.exe identified                |
| 2        | Locate files            | Open file location on service.exe                                   | %APPDATA%\Svservices found                                |
| 3        | Configuration           | Get-Content ...\client32.ini                                        | Gateways sonosarcx[.]com and sonosarcl[.]net on port 2080     |
| 4        | Network                 | ipconfig /displaydns \| Select-String sonosarc                      | No results                                                |
| 5        | Network                 | Get-NetTCPConnection -RemotePort 2080                               | No results                                                |
| 6        | Defender                | Get-WinEvent (Defender Operational) filtered                        | Detection and quarantine on 26/08/2026                    |
| 7        | Defender                | Same, sorted by time                                                | Earliest event 26/08/2026 11:19:40                        |
| 8        | Timeline                | (Get-Item ...\Svservices).CreationTime                              | 2 September 2025, 16:16:45                                |
| 9        | Process review          | Get-CimInstance Win32_Process (PID 6076), not elevated              | Empty: insufficient rights                                |
| 10       | Timeline                | Get-ChildItem (infection day, no -Force)                            | Three visible files only                                  |
| 11       | Timeline                | Get-ChildItem -Force ... Export-Csv to Desktop                      | Failed: OneDrive Desktop path and missing \$\_            |
| 12       | Timeline                | Get-ChildItem -Force ... Where-Object ... Export-Csv to home folder | Full timeline recovered                                   |
| 13       | Verification (elevated) | Get-AuthenticodeSignature; Zone.Identifier; Get-AppxPackage         | TradingView and easyroam genuine                          |
| 14       | Verification (elevated) | Get-CimInstance Win32_Process (servicehost.exe)                     | McAfee WebAdvisor, legitimate                             |
| 15       | Initial access          | Get-ItemProperty ...\RunMRU                                         | No malicious entries                                      |
| 16       | Initial access          | PSReadLine history search                                           | No delivery command                                       |
| 17       | Initial access          | Get-WinEvent MsiInstaller                                           | No events (log rolled over)                               |
| 18       | Intelligence            | Get-FileHash fe0.msi \| Set-Clipboard                               | SHA-256 obtained                                          |
| 19       | Intelligence            | VirusTotal lookups (fe0.msi and its parents)                        | NetSupport confirmed; loader and devenable[.]dev identified |

