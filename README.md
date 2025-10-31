# PC Hardware Report

A fully offline Windows system auditing tool that generates a detailed HTML report of your PC’s hardware — including CPU, GPU, RAM, motherboard, disks, network adapters, and power information — all without internet access or installation.

## Features

- Single EXE — no dependencies or installation required  
- Instant Report — outputs a full HTML hardware summary to your Desktop  
- Offline & Secure — no data leaves your machine  
- Complete Specs — collects hardware data via WMI/CIM, including:
  - CPU, GPU, and motherboard details  
  - Physical and logical disks  
  - RAM modules and speeds  
  - Network interfaces and IP configuration  
  - USB and audio devices  
  - Monitor EDID info (brand, size, serial)  
  - Active power plan  
- Export Formats: HTML, JSON, CSV (auto-generated for advanced users)

---

## Usage

### Option 1 — Run the EXE
1. Download `PC-Hardware-Report.exe` from the [Releases](../../releases) page.  
2. Double-click it.  
3. Wait a few seconds — your hardware report appears in a folder on your Desktop (for example, `PC_Hardware_Report.html`).

### Option 2 — Run the PowerShell Script
For advanced users who prefer source control or want to customize the report:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned -Force
.\PC-Hardware-Report.ps1
