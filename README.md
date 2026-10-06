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

<p align="center"><img src="screenshots/01-error-dialog.png" alt="Error dialog that triggered the investigation" width="800"></p>

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

<p align="center"><img src="screenshots/02-task-manager-processes.png" alt="task manager processes" width="800"></p>

*Figure 2: Task Manager
Details view showing service.exe (PID 22572) and servicehost.exe (PID
6076)*

<p align="center"><img src="screenshots/03-pid-query-not-elevated.png" alt="Non-elevated query for PID 6076 returning no path or command line" width="800"></p>

*Figure 3: Non-elevated query for PID 6076 returning no path or command
line*

#### Commands used at this stage

**Action:** Task Manager \> Details tab (sorted by name)

- **Purpose:** List all running processes with user, architecture and PID to spot anything unfamiliar.
- **Outcome:** Found service.exe (PID 22572, user `<user>`, 32-bit) and servicehost.exe (PID 6076, SYSTEM).

**Action:** Task Manager \> right-click service.exe \> Open file location

- **Purpose:** Find where the suspicious executable lives on disk.
- **Outcome:** Opened %APPDATA%\Svservices, the RAT staging folder.

```powershell
Get-CimInstance Win32_Process -Filter "ProcessId=6076" | select ExecutablePath,CommandLine
```
- **Purpose:** Get the path and command line of servicehost.exe.
- **Outcome:** Empty result. The window was not elevated, and standard users cannot read details of SYSTEM processes. Repeated later as administrator (section 4.7).


### 4.2 Staging folder

The launcher was located in `C:\Users\<user>\AppData\Roaming\Svservices`.
The folder name imitates "services" with a misspelling, a common
disguise. Its contents form a complete NetSupport client kit:

| **File**                                                                           | **Date modified** | **Size**  | **Role**                                                   |
|------------------------------------------------------------------------------------|-------------------|-----------|------------------------------------------------------------|
| service.exe                                                                        | 23/04/2025 23:05  | 116 KB    | Renamed NetSupport client (client32.exe)                   |
| client32.ini                                                                       | 08/08/2025 07:27  | 1 KB      | Client configuration including attacker gateways           |
| fe0 (fe0.msi)                                                                      | 02/09/2025 16:27  | 3,862 KB  | Windows Installer package that deployed the kit            |
| NSM.LIC                                                                            | 13/07/2012 19:26  | 1 KB      | Old cracked NetSupport licence reused across RAT campaigns |
| HTCTL32.DLL, TCCTL32.DLL, pcicapi.dll, PCICHEK.DLL, AudioCapture.dll, msvcr100.dll | 13/07/2025 18:09  | Various   | NetSupport support libraries                               |
| remcmdstub.exe                                                                     | 13/07/2025 18:09  | 59 KB     | NetSupport remote command component                        |
| NSM.ini, nsm_vpro.ini, nskbfltr.inf                                                | 13/07/2025 18:09  | 1 to 6 KB | NetSupport settings                                        |
| PCICL32.DLL                                                                        | n/a               | n/a       | Missing: quarantined by Defender on 26/08/2026             |

<p align="center"><img src="screenshots/04-svservices-folder.png" alt="svservices folder" width="800"></p>

*Figure 4: Contents of %APPDATA%\Svservices in File Explorer*

<p align="center"><img src="screenshots/05-folder-creation-time.png" alt="Earliest Defender events and the creation time of the Svservices folder (2 September 2025, 16:16:45)" width="800"></p>

*Figure 5: Earliest Defender events and the creation time of the
Svservices folder (showing 2 September 2025, 16:16:45)*

#### Commands used at this stage

**Action:** File Explorer: `C:\Users\<user>\AppData\Roaming\Svservices`

- **Purpose:** Inventory the files in the staging folder.
- **Outcome:** 14 files consistent with a NetSupport client kit; PCICL32.DLL missing.

```powershell
(Get-Item "$env:APPDATA\Svservices").CreationTime
```
- **Purpose:** Find when the folder was actually created, since file timestamps can be inherited from the attacker.
- **Outcome:** Tuesday 2 September 2025, 16:16:45. This became the infection anchor time.


### 4.3 Configuration analysis (client32.ini)

The configuration file was read as plain text without running anything.
It shows a client set up for covert, attacker-controlled use:

| **Setting**                                         | **Value**                             | **Meaning**                                                            |
|-----------------------------------------------------|---------------------------------------|------------------------------------------------------------------------|
| GatewayAddress                                      | sonosarcx[.]com:2080                    | Primary attacker command server                                        |
| SecondaryGateway                                    | sonosarcl[.]net:2080                    | Backup command server                                                  |
| Port / SecondaryPort                                | 2080                                  | Non-standard port for the HTTP gateway traffic                         |
| SysTray                                             | 0                                     | Hides the NetSupport tray icon from the user                           |
| quiet                                               | 1                                     | Suppresses licence prompts                                             |
| Usernames                                           | \*                                    | Works for any logged-in user                                           |
| silent / ShowUIOnConnect                            | 1 / 0                                 | No notification or window when the attacker connects                   |
| DisableDisconnect, DisableClientConnect             | 1                                     | User cannot end or control the remote session                          |
| DisableChatMenu, DisableMessage, DisableRequestHelp | 1                                     | Removes user-facing NetSupport features that could reveal its presence |
| Password, GSK, GSKX                                 | Encrypted values                      | Operator access credentials (attacker's, not the user's)               |
| \[\_Info\] Filename                                 | C:\Program Files (x86)\NetSupport\\.. | Path from the attacker's build machine                                 |

The domain names loosely imitate the Sonos brand. A web search at the
time of the investigation found no public reporting on either domain.

<p align="center"><img src="screenshots/06-client32-config-client.png" alt="client32.ini, [Client] section: silent operation, hidden tray icon and disabled user controls" width="800"></p>

*Figure 6: client32.ini, \[Client\] section: silent operation, hidden
tray icon and disabled user controls*

<p align="center"><img src="screenshots/07-client32-config-http.png" alt="client32.ini, [HTTP] section: gateways sonosarcx[.]com and sonosarcl[.]net on port 2080" width="800"></p>

*Figure 7: client32.ini, \[HTTP\] section: gateways sonosarcx[.]com and
sonosarcl[.]net on port 2080*

#### Commands used at this stage

```powershell
Get-Content "$env:APPDATA\Svservices\client32.ini"
```
- **Purpose:** Read the RAT configuration as plain text, without executing anything.
- **Outcome:** Revealed gateways sonosarcx[.]com:2080 and sonosarcl[.]net:2080, plus hidden-tray and silent settings.


### 4.4 Network activity

The DNS cache contained no entries for the "sonosarc" domains, and
`Get-NetTCPConnection -RemotePort 2080` returned no connections.
This is consistent with the RAT having been unable to run since its main
library was removed on 26 August 2026. No historical network logs were
available to show earlier connections.

#### Commands used at this stage

```powershell
ipconfig /displaydns | Select-String sonosarc
```
- **Purpose:** Check whether the host recently resolved either gateway domain.
- **Outcome:** No output: no recent lookups.

```powershell
Get-NetTCPConnection -RemotePort 2080 -ErrorAction SilentlyContinue
```
- **Purpose:** Check for live connections on the gateway port.
- **Outcome:** No output: no active command and control connection.


### 4.5 Microsoft Defender detection history

| **Time (local)**    | **Event**                                                                                                                                       |
|---------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| 26/08/2026 11:19:40 | Real-time protection detects HackTool:Win32/RemoteAdmin!MTB (severity High, category Tool) in Svservices\PCICL32.DLL while service.exe loads it |
| 26/08/2026 11:20:44 | Remediation applied: PCICL32.DLL quarantined; status "No additional actions required"                                                           |

These were the only Defender events matching the investigation keywords.
Defender classified the file as a "Tool" rather than a trojan, because
NetSupport is commercial software. It removed only the one detected
library and left the launcher, configuration, installer and persistence
in place. This explains both the late detection and the recurring error.

<p align="center"><img src="screenshots/08-network-checks-defender-quarantine.png" alt="DNS and port 2080 checks (no results), and the Defender quarantine event at 11:20:44" width="800"></p>

*Figure 8: DNS and port 2080 checks (no results), and the Defender
quarantine event at 11:20:44*

<p align="center"><img src="screenshots/09-defender-detection.png" alt="Defender detection event at 11:19:40 for PCICL32.DLL loaded by service.exe" width="800"></p>

*Figure 9: Defender detection event at 11:19:40 for PCICL32.DLL loaded
by service.exe*

#### Commands used at this stage

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
  ? Message -match "Svservices|PCICL32|NetSupport" |
  select TimeCreated,Message -First 20 |
  fl
```
- **Purpose:** Find Defender detections related to the RAT and what action was taken.
- **Outcome:** Two events on 26/08/2026: detection of HackTool:Win32/RemoteAdmin!MTB in PCICL32.DLL, then quarantine.

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
  ? Message -match "Svservices|PCICL32|NetSupport|servicehost" |
  sort TimeCreated |
  select TimeCreated -First 3
```
- **Purpose:** Find the earliest related detection, and check whether Defender ever flagged servicehost.exe.
- **Outcome:** Earliest event 26/08/2026 11:19:40. No earlier detections and no servicehost.exe events.


### 4.6 File system timeline for 2 September 2025

The staging folder was created on **2 September 2025 at 16:16:45**. A
recursive search of the user profile, including hidden folders, produced
the following sequence:

| **Time (local)** | **Artefact**                                                | **Interpretation**                                |
|------------------|-------------------------------------------------------------|---------------------------------------------------|
| 09:38:46         | Recent link to msftconnecttest.com redirect                 | Wi-Fi captive portal (on campus)                  |
| 14:18:20         | Recent link to info.h-brs.de eduroam page                   | University Wi-Fi set-up page                      |
| 14:18:31         | Downloads\easyroam.msix                                     | Genuine eduroam installer (verified, section 4.7) |
| 15:31:22         | AppData\Roaming\Microsoft\Crypto\Keys\\..                   | Routine Windows key file                          |
| 16:16:45         | AppData\Roaming\Svservices                                  | Staging folder created: infection begins          |
| 16:16:46         | Svservices\fe0.msi                                          | Malicious installer written one second later      |
| 16:16:52         | AppData\Local\NetSupport\NetSupport Manager                 | Installer runs and deploys NetSupport             |
| 16:21:30         | Downloads\TradingView (1).msix                              | Genuine TradingView installer (verified)          |
| 16:22:08         | AppData\Local\Packages\TradingView.Desktop\_...             | TradingView app installed                         |
| 16:54:46         | Temp\\..\CRX_INSTALL                                        | A Chrome extension was installed                  |
| 19:57:18         | Recent link to kycport.com                                  | Website visited                                   |
| 20:02:05         | Recent link to github.com TradingView-Crypto-developer-mode | GitHub page visited                               |

No file was created in the user profile between 15:31 and 16:16.
Whatever started the infection therefore left no file of its own behind,
which points to a command or script run directly rather than a
downloaded file that was opened.

<p align="center"><img src="screenshots/10-file-search-no-force.png" alt="First file search for 2 September 2025 without -Force: hidden folders skipped" width="800"></p>

*Figure 10: First file search for 2 September 2025 without -Force:
hidden folders skipped*

<p align="center"><img src="screenshots/11-file-search-force.png" alt="Elevated file search with -Force, showing hidden AppData artefacts from 2 September 2025" width="800"></p>

*Figure 11: Elevated file search with -Force, showing hidden AppData
artefacts from 2 September 2025*

<p align="center"><img src="screenshots/12-timeline-csv.png" alt="Timeline export (sep2_timeline.csv): Svservices, fe0.msi and NetSupport created 16:16:45 to 16:16:52, followed by the genuine TradingView install" width="800"></p>

*Figure 12: Timeline export (sep2_timeline.csv): Svservices, fe0.msi and
NetSupport created 16:16:45 to 16:16:52, followed by the genuine
TradingView install*

#### Commands used at this stage

```powershell
Get-ChildItem $env:USERPROFILE -Recurse -ErrorAction SilentlyContinue |
  ? { $_.CreationTime.Date -eq [datetime]'2025-09-02' } |
  select CreationTime,FullName |
  sort CreationTime
```
- **Purpose:** List every file created in the user profile on the infection day.
- **Outcome:** Three results: a personal document, easyroam.msix and TradingView (1).msix. Hidden folders such as AppData were skipped because -Force was missing.

**Attempt:** the same search with `-Force`, limited to 15:30 to 16:30, piped to `Export-Csv "$env:USERPROFILE\Desktop\sep2_timeline.csv"`

- **Purpose:** Include hidden folders and save the full result to a readable file.
- **Outcome:** Failed: "Could not find a part of the path". The Desktop is redirected to OneDrive, and the \$\_ variable was lost when the command was retyped.

```powershell
Get-ChildItem $env:USERPROFILE -Recurse -Force -ErrorAction SilentlyContinue |
  Where-Object CreationTime -ge ([datetime]'2025-09-02 15:30') |
  Where-Object CreationTime -le ([datetime]'2025-09-02 16:30') |
  Sort-Object CreationTime |
  Select-Object CreationTime,FullName |
  Export-Csv "$env:USERPROFILE\sep2_timeline.csv" -NoTypeInformation
notepad "$env:USERPROFILE\sep2_timeline.csv"
```
- **Purpose:** Same search, rewritten without \$\_ and saved to the home folder.
- **Outcome:** Succeeded. Showed Svservices at 16:16:45, fe0.msi at 16:16:46 and NetSupport Manager at 16:16:52, with nothing created between 15:31 and 16:16.


### 4.7 False leads ruled out

Several items were initially treated as suspicious and then checked.
Recording these is important because two early hypotheses turned out to
be wrong.

| **Item**                 | **Checks performed**                                                   | **Result**                                                                                                                                                                                                                                 |
|--------------------------|------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| TradingView (1).msix     | Authenticode signature; Zone.Identifier stream; installed AppX package | Genuine. Valid signature from TradingView, Inc. (Sectigo Public Code Signing CA R36, thumbprint 2480BCB9...BABE3D). Downloaded from tvd-packages.tradingview.com (ZoneId=3). Installed five minutes after the infection, so not the cause. |
| easyroam.msix            | Authenticode signature; installed AppX package                         | Genuine. Signed by DFN-Verein, Berlin (Sectigo Public Code Signing CA E36, thumbprint 90F46B75...D68C72F).                                                                                                                                 |
| servicehost.exe (SYSTEM) | Executable path and parent process (elevated session)                  | Legitimate. C:\Program Files\McAfee\WebAdvisor\ServiceHost.exe, started by services.exe (PID 1340). No second, SYSTEM-level foothold.                                                                                                      |

<p align="center"><img src="screenshots/13-signature-check.png" alt="Valid Authenticode signatures for the TradingView and easyroam installers" width="800"></p>

*Figure 13: Valid Authenticode signatures for the TradingView and
easyroam installers*

#### Commands used at this stage

```powershell
cd $env:USERPROFILE\Downloads; Get-AuthenticodeSignature "TradingView (1).msix","easyroam.msix" |
  fl Path,Status,SignerCertificate
```
- **Purpose:** Verify who signed the two installers downloaded that day.
- **Outcome:** Both Valid: TradingView, Inc. and DFN-Verein respectively.

```powershell
Get-Content "TradingView (1).msix" -Stream Zone.Identifier
```
- **Purpose:** Read the Mark of the Web to see where the file was downloaded from.
- **Outcome:** HostUrl was tvd-packages.tradingview.com: the official TradingView server.

```powershell
Get-AppxPackage | ? Name -match "trading|easyroam" | select Name,Publisher,InstallLocation
```
- **Purpose:** Confirm what was actually installed from those packages.
- **Outcome:** TradingView.Desktop and de.dfn.easyroam, both with the expected publishers.

```powershell
Get-CimInstance Win32_Process -Filter "Name='servicehost.exe'" |
  select ProcessId,ParentProcessId,ExecutablePath,CommandLine (elevated)
```
- **Purpose:** Resolve the SYSTEM process left over from section 4.1.
- **Outcome:** C:\Program Files\McAfee\WebAdvisor\ServiceHost.exe, parent PID 1340 (services.exe). Legitimate.

```powershell
Get-CimInstance Win32_Service |
  ? PathName -match 'servicehost' |
  select Name,StartMode,PathName
```
- **Purpose:** Check whether a service was registered under that name.
- **Outcome:** No suspicious service entry returned.


### 4.8 Initial access analysis

| **Source checked**                         | **Result**                                                                                                                                                                      |
|--------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| RunMRU (commands typed into Win+R)         | Only five benign entries: cmd, MDSCHED.EXE, mrt, msconfig, eventvwr. No malicious command, though the short list may mean older entries were cleared.                           |
| PowerShell history (PSReadLine)            | No delivery command. One unrelated entry was noted: a third-party script run from the internet with administrator rights (date unknown). |
| Windows Installer events (Application log) | No MsiInstaller events for 2 September 2025. The log has most likely rolled over in the year since.                                                                             |
| Browser history                            | Not available locally: Chrome keeps history for 90 days.                                                                                                                        |

Commands pasted into the Win+R box run PowerShell non-interactively and
do not appear in PowerShell history. Combined with the absence of any
dropped file before 16:16, this makes a fake verification prompt
("ClickFix") the most likely first step, but it could not be proven.

#### Commands used at this stage

```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
```
- **Purpose:** Look for a command pasted into the Win+R box (ClickFix pattern).
- **Outcome:** Only cmd, MDSCHED.EXE, mrt, msconfig and eventvwr. Nothing malicious.

```powershell
Get-Content (Get-PSReadLineOption).HistorySavePath |
  Select-String "msi|http|iwr|curl|mshta|Svservices"
```
- **Purpose:** Look for a download command typed into PowerShell.
- **Outcome:** No delivery command. One unrelated third-party script entry.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='MsiInstaller'; StartTime='2025-09-02 16:00'; EndTime='2025-09-02 16:30'} |
  Format-List TimeCreated,Message
```
- **Purpose:** Find the Windows Installer record of the fe0.msi installation.
- **Outcome:** "No events were found": the log has rolled over since 2025.


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

<p align="center"><img src="screenshots/14-msiinstaller-and-hashes.png" alt="No MsiInstaller events for 2 September 2025, and SHA-256 hashes of fe0.msi and service.exe" width="800"></p>

*Figure 14: No MsiInstaller events for 2 September 2025, and SHA-256
hashes of fe0.msi and service.exe*

<p align="center"><img src="screenshots/15-virustotal-detection.png" alt="VirusTotal detection page for fe0.msi (11/62, hacktool.netsup)" width="800"></p>

*Figure 15: VirusTotal detection page for fe0.msi (11/62,
hacktool.netsup)*

<p align="center"><img src="screenshots/16-virustotal-details.png" alt="VirusTotal Details tab for fe0.msi showing file hashes and type" width="800"></p>

*Figure 16: VirusTotal Details tab for fe0.msi showing file hashes and
type*

<p align="center"><img src="screenshots/17-virustotal-execution-parents.png" alt="VirusTotal Relations: contacted IP addresses and execution parents (crap.zip and the PowerShell loader)" width="800"></p>

*Figure 17: VirusTotal Relations: contacted IP addresses and execution
parents (crap.zip and the PowerShell loader)*

<p align="center"><img src="screenshots/18-virustotal-bundled-dropped.png" alt="VirusTotal Relations: bundled and dropped files, including Binary.aicustact.dll" width="800"></p>

*Figure 18: VirusTotal Relations: bundled and dropped files, including
Binary.aicustact.dll*

<p align="center"><img src="screenshots/19-virustotal-contacted-domains.png" alt="VirusTotal Relations: contacted domains (benign Microsoft, Akamai and Let&#39;s Encrypt traffic)" width="800"></p>

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

<p align="center"><img src="screenshots/20-virustotal-loader-code-insights.jpg" alt="VirusTotal Code Insights for the PowerShell loader, naming devenable[.]dev/fe0.msi" width="800"></p>

*Figure 20: VirusTotal Code Insights for the PowerShell loader, naming
devenable[.]dev/fe0.msi*

Report links: [fe0.msi on
VirusTotal](https://www.virustotal.com/gui/file/528373aa38e1139ce6b5325ef25cc756de2162c9ca58f7fbec2afaf8e3ceab1c);
[PowerShell loader on
VirusTotal](https://www.virustotal.com/gui/file/ea4de238a6ce0943c9eebf367ceb76d777a8c68c45c61da067c363923cec1813).

#### Commands used at this stage

```powershell
Get-FileHash "$env:APPDATA\Svservices\fe0.msi","$env:APPDATA\Svservices\service.exe" |
  Format-List Hash,Path
```
- **Purpose:** Generate SHA-256 hashes for threat intelligence lookups.
- **Outcome:** fe0.msi: 528373aa...3ceab1c; service.exe: ee60df2b...7ebb14f3.

```powershell
(Get-FileHash "$env:APPDATA\Svservices\fe0.msi").Hash | Set-Clipboard
```
- **Purpose:** Copy the hash without retyping 64 characters.
- **Outcome:** Hash pasted into VirusTotal search.

**Action:** virustotal.com \> Search \> paste hash \> Detection, Details, Relations tabs

- **Purpose:** Check reputation, build history, related files and network behaviour.
- **Outcome:** 11/62 detections (hacktool.netsup); build date 8 August 2025; PowerShell execution parent identified.

**Action:** VirusTotal \> Relations \> Execution Parents \> malicous.msi

- **Purpose:** Find out what launched the installer.
- **Outcome:** PowerShell loader that downloads devenable[.]dev/fe0.msi into Svservices and runs msiexec silently.


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

