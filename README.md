<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized Tor Usage
- [Scenario Creation](https://github.com/madelynncharron/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using Tor browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known Tor entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any Tor usage and analyze related security incidents to mitigate potential risks. If any use of Tor is found, notify management.

### High-Level Tor-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known Tor ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that contains “tor” and discovered that the user "labuser" downloaded a Tor installer. This resulted in many Tor-related files being copied to the desktop and creation of a file named `tor-shopping-list.txt` at `2026-03-06T17:49:05.185797Z`.

**These events occured at: `2026-03-06T17:49:05.185797Z (9:36:31 AM)`**

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "mde-test"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "labuser"
| where Timestamp >= datetime(2026-03-06T00:13:16.8668917Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, Account = InitiatingProcessAccountName
```
<img width="1020" height="622" alt="image" src="https://github.com/user-attachments/assets/d84909f8-4451-4d91-8c9a-6c8b95d14160" />



---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained “tor-browser-windows”. Based on the logs returned at `2026-03-06T17:36:03.2766091Z`, a user on device “mde-test” ran an executable named `tor-browser-windows-x86_64-portable-15.0.7.exe` from the Downloads folder using a command to silently install the Tor browser. 

**These events occured at: `2026-03-06T17:36:03.2766091Z (9:36:03 AM)`**

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "mde-test"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.7.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
```
<img width="1272" height="220" alt="image" src="https://github.com/user-attachments/assets/f5fe5e25-ca80-4c1c-b286-71e2c6c17117" />


---

### 3. Searched the `DeviceProcessEvents` Table for Tor Browser Execution

Searched for any `FileName` that had “tor.exe” or “firefox.exe” to see if there was any indication that “labuser” opened the Tor browser. There was evidence that the user did open the tor browser at `2026-03-06T17:36:43.5229446Z`. There were several other instances of `firefox.exe` (Tor) and `tor.exe` opened afterwards.

**These events occured at: ` 2026-03-06T17:36:43.5229446Z (9:36:43 AM)`**

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "mde-test"  
| where FileName has_any ("tor.exe", "firefox.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1265" height="1074" alt="image" src="https://github.com/user-attachments/assets/8873a91b-a795-4fc0-a235-bd2cd6887e68" />


---

### 4. Searched the `DeviceNetworkEvents` Table for Tor Network Connections

Searched for any indication that the Tor browser was used to establish a connection to any of the known Tor ports. At `2026-03-06T17:38:51.6053804Z`, a user on “mde-test” device successfully established a connection to the remote IP address `185.150.28.13` on port `9001`. The connection was initiated by the `tor.exe` process located in folder `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a few other connections on port `443` as well.

**These events occured at: `2026-03-06T17:38:51.6053804Z (9:38:51 AM)`**

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "mde-test"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl  
| order by Timestamp desc
```
<img width="1261" height="417" alt="image" src="https://github.com/user-attachments/assets/056e4ff4-25e6-44c7-b76f-92dfcddd698d" />


---

## Chronological Event Timeline 

### 1. File Download - Tor Installer

- **Timestamp:** `2026-03-06T17:36:03.2766091Z (9:36:03 AM)` 
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 2. Process Execution - Tor Browser Installation

- **Timestamp:** `2026-03-06T17:49:05.185797Z (9:36:31 AM)`
- **Event:** The user "labuser" executed the file `tor-browser-windows-x86_64-portable-15.0.7.exe` in silent mode, initiating a background installation of the Tor Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.7.exe /S`
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-15.0.7.exe`

### 3. Process Execution - Tor Browser Launch

- **Timestamp:** `2026-03-06T17:36:43.5229446Z (9:36:43 AM)`
- **Event:** User "labuser" opened the Tor browser. Subsequent processes associated with Tor browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of Tor browser-related executables detected.
- **File Path:** `C:\Users\labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - Tor Network

- **Timestamp:** `2026-03-06T17:38:51.6053804Z (9:38:51 AM)`
- **Event:** A network connection to IP `185.150.28.13` on port `9001` by user "labuser" was established using `tor.exe`, confirming Tor browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - Tor Browser Activity

- **Timestamps:**
  - `2026-03-06T17:38:49.8690516Z (9:38:49 AM)` - Connected to `96.9.98.161` and `185.177.126.118` on port `443`.
- **Event:** Additional Tor network connections were established, indicating ongoing activity by user "labuser" through the Tor browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - Tor Shopping List

- **Timestamp:** `2026-03-06T17:49:05.185797Z (9:49:05 AM)`
- **Event:** The user "labuser" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their Tor browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Desktop\tor-shopping-list.txt`

---

## Summary

The user "labuser" on the "mde-test" device initiated and completed the installation of the Tor browser. They proceeded to launch the browser, establish connections within the Tor network, and created various files related to Tor on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the Tor browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

Tor usage was confirmed on the endpoint `mde-test` by the user `labuser`. The device was isolated, and the user's direct manager was notified.

---
